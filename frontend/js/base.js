/* global MathJax */

/* eslint-disable
    camelcase,
    max-len,
    no-useless-escape,
*/
// TODO: This file was created by bulk-decaffeinate.
// Fix any style issues and re-enable lint.
/*
 * decaffeinate suggestions:
 * DS101: Remove unnecessary use of Array.from
 * DS102: Remove unnecessary code created because of implicit returns
 * DS103: Rewrite code to no longer use __guard__
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */

import './libraries'
import './infrastructure/error-reporter'
import './modules/recursionHelper'
import './modules/errorCatcher'
import './modules/localStorage'
import './modules/sessionStorage'
import getMeta from './utils/meta'

const App = angular
  .module('SharelatexApp', [
    'ui.bootstrap',
    'autocomplete',
    'RecursionHelper',
    'ng-context-menu',
    'ngSanitize',
    'ipCookie',
    'ErrorCatcher',
    'localStorage',
    'sessionStorage',
    'ui.select',
  ])
  .config(function ($qProvider, $httpProvider, uiSelectConfig) {
    $qProvider.errorOnUnhandledRejections(false)
    uiSelectConfig.spinnerClass = 'fa fa-refresh ui-select-spin'

    return __guard__(
      typeof MathJax !== 'undefined' && MathJax !== null
        ? MathJax.Hub
        : undefined,
      x =>
        x.Config({
          messageStyle: 'none',
          imageFont: null,
          // Fast preview, introduced in 2.5, is unhelpful due to extra codemirror refresh
          // and disabling it avoids issues with math processing errors
          // github.com/overleaf/write_latex/pull/1375
          'fast-preview': { disabled: true },
          'HTML-CSS': {
            availableFonts: ['TeX'],
            // MathJax's automatic font scaling does not work well when we render math
            // that isn't yet on the page, so we disable it and set a global font
            // scale factor
            scale: 110,
            matchFontHeight: false,
          },
          TeX: {
            equationNumbers: { autoNumber: 'AMS' },
            useLabelIDs: false,
          },
          skipStartupTypeset: true,
          tex2jax: {
            processEscapes: true,
            // Dollar delimiters are added by the mathjax directive
            inlineMath: [['\\(', '\\)']],
            displayMath: [
              ['$$', '$$'],
              ['\\[', '\\]'],
            ],
          },
        })
    )
  })

App.run(($rootScope, $templateCache) => {
  $rootScope.usersEmail = getMeta('ol-usersEmail')

  // UI Select templates are hard-coded and use Glyphicon icons (which we don't import).
  // The line below simply overrides the hard-coded template with our own, which is
  // basically the same but using Font Awesome icons.
  $templateCache.put(
    'bootstrap/match.tpl.html',
    '<div class="ui-select-match" ng-hide="$select.open && $select.searchEnabled" ng-disabled="$select.disabled" ng-class="{\'btn-default-focus\':$select.focus}"><span tabindex="-1" class="btn btn-default form-control ui-select-toggle" aria-label="{{ $select.baseTitle }} activate" ng-disabled="$select.disabled" ng-click="$select.activate()" style="outline: 0;"><span ng-show="$select.isEmpty()" class="ui-select-placeholder text-muted">{{$select.placeholder}}</span> <span ng-hide="$select.isEmpty()" class="ui-select-match-text pull-left" ng-class="{\'ui-select-allow-clear\': $select.allowClear && !$select.isEmpty()}" ng-transclude=""></span> <i class="caret pull-right" ng-click="$select.toggle($event)"></i> <a ng-show="$select.allowClear && !$select.isEmpty() && ($select.disabled !== true)" aria-label="{{ $select.baseTitle }} clear" style="margin-right: 10px" ng-click="$select.clear($event)" class="btn btn-xs btn-link pull-right"><i class="fa fa-times" aria-hidden="true"></i></a></span></div>'
  )
})

const sl_debugging = window.location.search.match(/debug=true/)
window.sl_debugging = sl_debugging // make a global flag for debugging code
window.sl_console = sl_debugging ? console : { log() {} }

export default App

function __guard__(value, transform) {
  return typeof value !== 'undefined' && value !== null
    ? transform(value)
    : undefined
}
