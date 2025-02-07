import React, { useRef, useEffect } from 'react'
import PropTypes from 'prop-types'
import Linkify from 'react-linkify'

function MessageContent({ content }) {
  const root = useRef(null)

  useEffect(() => {
    if (!(window.MathJax && window.MathJax.Hub)) {
      return
    }
    const MJHub = window.MathJax.Hub
    const inlineMathConfig =
      (MJHub.config &&
        MJHub.config.tex2jax &&
        MJHub.config.tex2jax.inlineMath) ||
      []
    const alreadyConfigured = inlineMathConfig.some(
      c => c[0] === '$' && c[1] === '$'
    )
    if (!alreadyConfigured) {
      MJHub.Config({
        tex2jax: {
          inlineMath: inlineMathConfig.concat([['$', '$']]),
        },
      })
    }
  }, [])

  useEffect(() => {
    // adds attributes to all the links generated by <Linkify/>, required due to https://github.com/tasti/react-linkify/issues/99
    for (const a of root.current.getElementsByTagName('a')) {
      a.setAttribute('target', '_blank')
      a.setAttribute('rel', 'noreferrer noopener')
    }

    // MathJax typesetting
    const MJHub = window.MathJax.Hub
    const timeoutHandler = setTimeout(() => {
      MJHub.Queue(['Typeset', MJHub, root.current])
    }, 0)
    return () => clearTimeout(timeoutHandler)
  }, [content])

  return (
    <p ref={root}>
      <Linkify>{content}</Linkify>
    </p>
  )
}

MessageContent.propTypes = {
  content: PropTypes.string.isRequired,
}

export default MessageContent
