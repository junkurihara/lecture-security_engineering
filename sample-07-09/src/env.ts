export const getJscu = () => {
  if(typeof window !== 'undefined' && typeof (<any>window).jscu !== 'undefined'){
    return (<any>window).jscu;
  }
  else return require('js-crypto-utils');
};
