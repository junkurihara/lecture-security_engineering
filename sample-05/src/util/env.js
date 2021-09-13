import jscu from 'js-crypto-utils';
import jscec from 'js-crypto-ec';

/**
 * Get jscu
 */
export const getJscu = () => {
  const global = Function('return this;')();
  if (typeof window !== 'undefined'){
    return window.jscu;
  }
  else{
    global.jscu = jscu;
    return jscu;
  }
};

/**
 * Get ec
 */
export const getJscec = () => {
  const global = Function('return this;')();
  if (typeof window !== 'undefined'){
    return window.jscec;
  }
  else{
    global.jscec = jscec;
    return jscec;
  }
};
