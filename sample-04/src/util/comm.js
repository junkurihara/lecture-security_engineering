import {getFetch} from './env.js';

/**
 * make RESTful API call to the security hub api.
 * @param method {String} - 'GET' or 'POST'
 * @param requestUrl {String} - url connected with the endpoint defined above.
 * @param payload {Object} - request body.
 * @param headers - header params.
 * @param mode
 * @return {Promise<*>}
 */
export const makeApiCall = async ({method, requestUrl, payload=null, headers=null, mode='cors'}) => {
  //logger.debug('make API call to AWS API Gateway');
  const fetch = getFetch();
  const body = (payload)? JSON.stringify(payload) : null;
  const response = await fetch(requestUrl, {
    method,
    body,
    headers,
    mode
  });

  let success = false;
  if (response.status >= 200 && response.status < 300) {
    success = true;
  }

  const responseJson = await response.json();
  if(success) {
    return responseJson;
  }
  else {
    const err = Object.assign({status: response.status, statusText: response.statusText}, responseJson);
    throw new Error(JSON.stringify(err));
  }
};
