const path = require('path');
// const webpack = require('webpack');
const base = require('./webpack.baseconfig.json');

const config = {
  entry: ['./src/index.js'],

  output: {
    filename: `${base.libName}.bundle.js`,
    chunkFilename: '[name].js',
    path: path.resolve(__dirname, './dist'),
    publicPath: path.resolve(__dirname, './dist'),
    library: base.libName,
    libraryTarget: 'umd',
    globalObject: 'this' // for node js import
  },
  resolve: {
    extensions: ['.js', '.jsx', '.mjs'],
    modules: ['node_modules']
  },
  module: {
    rules: [
      {
        test: /\.(m|)js$/,
        use: [{
          loader: 'babel-loader'
        }],
        exclude: path.join(__dirname, 'node_modules') // exclude: /node_modules/
      },
    ],
  },
  externals: {
    crypto: true,
    'cross-fetch': true
  }
};

module.exports = (env, argv) => {
  config.mode = (typeof argv.mode !== 'undefined' && argv.mode === 'production') ? argv.mode : 'development';

  if (config.mode === 'production') console.log('Webpack for production');
  else{
    console.log('Webpack for development');
    config.devtool = 'inline-source-map'; // add inline source map
  }

  return config;
};
