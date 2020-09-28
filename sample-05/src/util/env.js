/**
 * Get jscu
 */
export const getJscu = () => {
  let jscu;
  const global = Function('return this;')();
  if (typeof window !== 'undefined'){
    jscu = window.jscu;
  }
  else{
    jscu = require('js-crypto-utils');
    global.jscu = jscu;
  }

  return jscu;
};

/**
 * Get ec
 */
export const getJscec = () => {
  let jscec;
  const global = Function('return this;')();
  if (typeof window !== 'undefined'){
    jscec = window.jscec;
  }
  else{
    jscec = require('js-crypto-ec');
    global.jscec = jscec;
  }

  return jscec;
};
