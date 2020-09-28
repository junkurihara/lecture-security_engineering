/**
 * webpack.dev.js
 */
const common = require('./webpack.common.js');
const webpack = require('webpack');
const merge = require('webpack-merge');

// webpack main configration
const webpackConfig = {
  mode: 'development',
  plugins:[
    new webpack.optimize.LimitChunkCountPlugin({ maxChunks: 1 }),
    new webpack.optimize.MinChunkSizePlugin({minChunkSize: 1000}),
    new webpack.DefinePlugin({
      'process.env': {
        TEST_ENV: JSON.stringify(process.env.TEST_ENV),
      }
    })
  ],
  devtool: 'inline-source-map' // add inline source map
};

// export main configuration adjusted to various environments
module.exports = (env, argv) => {
  if (argv.mode !== 'development') throw new Error('Not development mode!!');
  ////////////////////////////////////////////////////////////////////////
  // library build setting
  return merge.merge(common.webpackConfig, webpackConfig);
};
