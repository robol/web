const { db, ObjectId } = require('../../infrastructure/mongodb')
const OError = require('@overleaf/o-error')
const async = require('async')
const { promisifyAll } = require('../../util/promises')
const { Subscription } = require('../../models/Subscription')
const SubscriptionLocator = require('./SubscriptionLocator')
const UserGetter = require('../User/UserGetter')
const PlansLocator = require('./PlansLocator')
const FeaturesUpdater = require('./FeaturesUpdater')
const { DeletedSubscription } = require('../../models/DeletedSubscription')

const SubscriptionUpdater = {
  /**
   * Change the admin of the given subscription.
   *
   * If the subscription is a group, add the new admin as manager while keeping
   * the old admin. Otherwise, replace the manager.
   *
   * Validation checks are assumed to have been made:
   *   * subscription exists
   *   * user exists
   *   * user does not have another subscription
   *   * subscription is not a Recurly subscription
   *
   * If the subscription is Recurly, we silently do nothing.
   */
  updateAdmin(subscription, adminId, callback) {
    const query = {
      _id: ObjectId(subscription._id),
      customAccount: true,
    }
    const update = {
      $set: { admin_id: ObjectId(adminId) },
    }
    if (subscription.groupPlan) {
      update.$addToSet = { manager_ids: ObjectId(adminId) }
    } else {
      update.$set.manager_ids = [ObjectId(adminId)]
    }
    Subscription.updateOne(query, update, callback)
  },

  syncSubscription(recurlySubscription, adminUserId, requesterData, callback) {
    if (!callback) {
      callback = requesterData
      requesterData = {}
    }
    SubscriptionLocator.getUsersSubscription(
      adminUserId,
      function (err, subscription) {
        if (err != null) {
          return callback(err)
        }
        if (subscription != null) {
          SubscriptionUpdater._updateSubscriptionFromRecurly(
            recurlySubscription,
            subscription,
            requesterData,
            callback
          )
        } else {
          SubscriptionUpdater._createNewSubscription(
            adminUserId,
            function (err, subscription) {
              if (err != null) {
                return callback(err)
              }
              SubscriptionUpdater._updateSubscriptionFromRecurly(
                recurlySubscription,
                subscription,
                requesterData,
                callback
              )
            }
          )
        }
      }
    )
  },

  addUserToGroup(subscriptionId, userId, callback) {
    SubscriptionUpdater.addUsersToGroup(subscriptionId, [userId], callback)
  },

  addUsersToGroup(subscriptionId, memberIds, callback) {
    SubscriptionUpdater.addUsersToGroupWithoutFeaturesRefresh(
      subscriptionId,
      memberIds,
      function (err) {
        if (err != null) {
          return callback(err)
        }
        async.map(
          memberIds,
          function (userId, cb) {
            FeaturesUpdater.refreshFeatures(userId, 'add-to-group', cb)
          },
          callback
        )
      }
    )
  },

  addUsersToGroupWithoutFeaturesRefresh(subscriptionId, memberIds, callback) {
    const searchOps = { _id: subscriptionId }
    const insertOperation = { $addToSet: { member_ids: { $each: memberIds } } }

    Subscription.updateOne(searchOps, insertOperation, callback)
  },

  removeUserFromGroups(filter, userId, callback) {
    const removeOperation = { $pull: { member_ids: userId } }
    Subscription.updateMany(filter, removeOperation, function (err) {
      if (err != null) {
        OError.tag(err, 'error removing user from groups', {
          filter,
          removeOperation,
        })
        return callback(err)
      }
      UserGetter.getUser(userId, function (error, user) {
        if (error) {
          return callback(error)
        }
        FeaturesUpdater.refreshFeatures(
          userId,
          'remove-user-from-groups',
          callback
        )
      })
    })
  },

  removeUserFromGroup(subscriptionId, userId, callback) {
    SubscriptionUpdater.removeUserFromGroups(
      { _id: subscriptionId },
      userId,
      callback
    )
  },

  removeUserFromAllGroups(userId, callback) {
    SubscriptionLocator.getMemberSubscriptions(
      userId,
      function (error, subscriptions) {
        if (error) {
          return callback(error)
        }
        if (!subscriptions) {
          return callback()
        }
        const subscriptionIds = subscriptions.map(sub => sub._id)
        SubscriptionUpdater.removeUserFromGroups(
          { _id: subscriptionIds },
          userId,
          callback
        )
      }
    )
  },

  deleteWithV1Id(v1TeamId, callback) {
    Subscription.deleteOne({ 'overleaf.id': v1TeamId }, callback)
  },

  deleteSubscription(subscription, deleterData, callback) {
    if (callback == null) {
      callback = function () {}
    }
    async.series(
      [
        cb =>
          // 1. create deletedSubscription
          SubscriptionUpdater._createDeletedSubscription(
            subscription,
            deleterData,
            cb
          ),
        cb =>
          // 2. remove subscription
          Subscription.deleteOne({ _id: subscription._id }, cb),
        cb =>
          // 3. refresh users features
          SubscriptionUpdater._refreshUsersFeatures(subscription, cb),
      ],
      callback
    )
  },

  restoreSubscription(subscriptionId, callback) {
    SubscriptionLocator.getDeletedSubscription(
      subscriptionId,
      function (err, deletedSubscription) {
        if (err) {
          return callback(err)
        }
        const subscription = deletedSubscription.subscription
        async.series(
          [
            cb =>
              // 1. upsert subscription
              db.subscriptions.updateOne(
                { _id: subscription._id },
                subscription,
                { upsert: true },
                cb
              ),
            cb =>
              // 2. refresh users features. Do this before removing the
              //    subscription so the restore can be retried if this fails
              SubscriptionUpdater._refreshUsersFeatures(subscription, cb),
            cb =>
              // 3. remove deleted subscription
              DeletedSubscription.deleteOne(
                { 'subscription._id': subscription._id },
                callback
              ),
          ],
          callback
        )
      }
    )
  },

  _refreshUsersFeatures(subscription, callback) {
    const userIds = [subscription.admin_id].concat(
      subscription.member_ids || []
    )
    async.mapSeries(
      userIds,
      function (userId, cb) {
        FeaturesUpdater.refreshFeatures(userId, 'subscription-updater', cb)
      },
      callback
    )
  },

  _createDeletedSubscription(subscription, deleterData, callback) {
    subscription.teamInvites = []
    subscription.invited_emails = []
    const filter = { 'subscription._id': subscription._id }
    const data = {
      deleterData: {
        deleterId: deleterData.id,
        deleterIpAddress: deleterData.ip,
      },
      subscription: subscription,
    }
    const options = { upsert: true, new: true, setDefaultsOnInsert: true }
    DeletedSubscription.findOneAndUpdate(filter, data, options, callback)
  },

  _createNewSubscription(adminUserId, callback) {
    const subscription = new Subscription({
      admin_id: adminUserId,
      manager_ids: [adminUserId],
    })
    subscription.save(err => callback(err, subscription))
  },

  _deleteAndReplaceSubscriptionFromRecurly(
    recurlySubscription,
    subscription,
    requesterData,
    callback
  ) {
    const adminUserId = subscription.admin_id
    SubscriptionUpdater.deleteSubscription(subscription, requesterData, err => {
      if (err) {
        return callback(err)
      }
      SubscriptionUpdater._createNewSubscription(
        adminUserId,
        (err, newSubscription) => {
          if (err) {
            return callback(err)
          }
          SubscriptionUpdater._updateSubscriptionFromRecurly(
            recurlySubscription,
            newSubscription,
            requesterData,
            callback
          )
        }
      )
    })
  },

  _updateSubscriptionFromRecurly(
    recurlySubscription,
    subscription,
    requesterData,
    callback
  ) {
    if (recurlySubscription.state === 'expired') {
      return SubscriptionUpdater.deleteSubscription(
        subscription,
        requesterData,
        callback
      )
    }
    const updatedPlanCode = recurlySubscription.plan.plan_code
    const plan = PlansLocator.findLocalPlanInSettings(updatedPlanCode)

    if (plan == null) {
      return callback(new Error(`plan code not found: ${updatedPlanCode}`))
    }
    if (!plan.groupPlan && subscription.groupPlan) {
      // If downgrading from group to individual plan, delete group sub and create a new one
      return SubscriptionUpdater._deleteAndReplaceSubscriptionFromRecurly(
        recurlySubscription,
        subscription,
        requesterData,
        callback
      )
    }

    subscription.recurlySubscription_id = recurlySubscription.uuid
    subscription.planCode = updatedPlanCode

    if (plan.groupPlan) {
      if (!subscription.groupPlan) {
        subscription.member_ids = subscription.member_ids || []
        subscription.member_ids.push(subscription.admin_id)
      }

      subscription.groupPlan = true
      subscription.membersLimit = plan.membersLimit

      // Some plans allow adding more seats than the base plan provides.
      // This is recorded as a subscription add on.
      if (
        plan.membersLimitAddOn &&
        Array.isArray(recurlySubscription.subscription_add_ons)
      ) {
        recurlySubscription.subscription_add_ons.forEach(addOn => {
          if (addOn.add_on_code === plan.membersLimitAddOn) {
            subscription.membersLimit += addOn.quantity
          }
        })
      }
    }
    subscription.save(function (error) {
      if (error) {
        return callback(error)
      }
      SubscriptionUpdater._refreshUsersFeatures(subscription, callback)
    })
  },
}

SubscriptionUpdater.promises = promisifyAll(SubscriptionUpdater)
module.exports = SubscriptionUpdater
