const axios = require('axios')
const querystring = require('querystring')
const crypto = require('crypto')
const http = require('http')

http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://api.twitter.com/*')
  res.setHeader('Access-Control-Allow-Origin', '<Client URL>')
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Credentials', 'true')

  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Max-Age', 6000)
    res.writeHead(204, {
      "Content-Type": "text/plain"
    })
    res.write('')
    res.end()
  } else if (req.method === 'POST') {
    // TODO: checked cookie's id with database's id
    let responseData = ''
    req.on('data', (response) => {
      responseData = JSON.parse(response).data + ''
    })
    req.on('end', () => {
      const requestMethod = new TwitterOAuthUtils()
      const paramsRequestToken = requestMethod.getPramsRequestToken()
      if (responseData === 'request_token' && requestMethod.getOAuthData().oauthVerifier === '') {
        requestMethod.getRequestToken(paramsRequestToken)
          .then((tokenOAuth) => {
            if (tokenOAuth != null && tokenOAuth.oauth_token) {
              const oauthUri = encodeURI(`https://api.twitter.com/oauth/authorize?oauth_token=${encodeURIComponent(tokenOAuth.oauth_token)}`)
              res.writeHead(200, {
                'Content-Type': 'application/json'
              })
              res.write(JSON.stringify({ response: oauthUri }))
            }
          }).catch((err) => {
            console.error(err)
            res.writeHead(404, {
              'Content-Type': 'application/json'
            })
            res.write('error!')
          }).finally(() => {
            res.end()
          })
      } else {
        res.writeHead(404, {
          'Content-Type': 'application/json'
        })
        res.write('error!')
        res.end()
      }
    })
  } else if (req.method === 'GET') {
    const reqURI = req.url
    if (reqURI && reqURI.includes('oauth_verifier')) {
      const tmpURI = reqURI.replace('/?', '')
      const requestMethod = new TwitterOAuthUtils()
      requestMethod.setOAuthData(querystring.parse(tmpURI).oauth_verifier, 'oauthVerifier')
      requestMethod.setOAuthData(querystring.parse(tmpURI).oauth_token, 'oauthToken')
      const paramsAccessToken = requestMethod.getParamsAccessToken(requestMethod)
      requestMethod.getAccessToken(paramsAccessToken).then((data) => {
        if (typeof data.oauth_token === 'string' && typeof data.oauth_token_secret === 'string') {
          requestMethod.setOAuthData(data.oauth_token, 'oauthToken')
          requestMethod.setOAuthData(data.oauth_token_secret, 'oauthTokenSecret')
          const keyOfToken = crypto.createHmac('sha256', data.oauth_token + querystring.parse(tmpURI).oauth_verifier)
          requestMethod.setOAuthData(keyOfToken.digest('base64'), 'oauthHashKey')
          const tmpDate = new Date()
          tmpDate.setDate(tmpDate.getDate() + 5)
          res.writeHead(302, {
            'Location': `<Client URL>/?id=${requestMethod.getOAuthData().oauthHashKey}`,
          })
          res.write('redirect!')
        }
      }).catch((err) => {
        console.error(err)
        res.writeHead(400, {
          "Content-Type": "application/json"
        })
        res.write('error!')
      }).finally(() => {
        res.end()
      })
    } else {
      res.writeHead(408, {
        'Content-Type': 'application/json'
      })
      res.write('error!')
      res.end()
    }
  } else {
    res.writeHead(404, {
      'Content-Type': 'application/json'
    })
    res.write('error!')
    res.end()
  }
}).listen(process.env.PORT ? process.env.PORT : 8080)

console.log(`${process.env.PORT}: start...`)

class TwitterOAuthUtils {
  constructor() {
    this.dataOAuth = Object.seal({
      oauthToken: '',
      oauthTokenSecret: '',
      oauthVerifier: '',
      // oauthVerifierとユーザ名のハッシュ化した値の保持などに利用
      oauthHashKey: '',
    })
  }

  getRequestTokenUrl = 'https://api.twitter.com/oauth/request_token'
  getAccessTokenUrl = 'https://api.twitter.com/oauth/access_token'
  callbackUrl = '<Server URL>'
  consumerKey = 'comsumer_key'
  consumerSecret = 'comsumer_secret_key'
  keyOfSign = encodeURIComponent(this.consumerSecret) + '&'

  getOAuthData() {
    return this.dataOAuth
  }
  setOAuthData(props, reqProps) {
    if (!props) return
    switch (reqProps) {
      case 'oauthToken':
        this.dataOAuth.oauthToken = props
        return
      case 'oauthTokenSecret':
        this.dataOAuth.oauthTokenSecret = props
        return
      case 'oauthVerifier':
        this.dataOAuth.oauthVerifier = props
        return
      case 'oauthHashKey':
        this.dataOAuth.oauthHashKey = props
        return
      default:
        return
    }
  }

  getPramsRequestToken = () => ({
    oauth_callback: this.callbackUrl,
    oauth_consumer_key: this.consumerKey,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: (() => {
      const date = new Date()
      return Math.floor(date.getTime() / 1000)
    })(),
    oauth_nonce: (() => {
      const date = new Date()
      return date.getTime()
    })(),
    oauth_version: '1.0',
  })

  getParamsAccessToken = (twitterOAuthUtils) => {
    return {
      consumer_key: this.consumerKey,
      oauth_token: twitterOAuthUtils.getOAuthData().oauthToken,
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: (() => {
        const date = new Date()
        return Math.floor(date.getTime() / 1000)
      })(),
      oauth_verifier: twitterOAuthUtils.getOAuthData().oauthVerifier,
      oauth_nonce: (() => {
        const date = new Date()
        return date.getTime()
      })(),
      oauth_version: '1.0'
    }
  }

  async getRequestToken(params) {
    const tmpParams = {}
    Object.keys(params).forEach((item) => {
      tmpParams[`${item}`] = encodeURIComponent(params[`${item}`])
    })

    const requestParams = Object.keys(tmpParams).map((item) => {
      return `${item}=${tmpParams[`${item}`]}`
    }).sort((a, b) => {
      if (a < b) return -1
      if (a > b) return 1
      return 0
    }).join('&')

    const dataOfSign = `${encodeURIComponent('POST')}&${encodeURIComponent(this.getRequestTokenUrl)}&${encodeURIComponent(requestParams)}`
    const signature = crypto.createHmac('sha1', this.keyOfSign).update(dataOfSign).digest('base64')

    tmpParams['oauth_signature'] = encodeURIComponent(signature)
    const headerParams = Object.keys(tmpParams).map((item) => {
      return `${item}=${tmpParams[`${item}`]}`
    }).join(',')

    const header = {
      Authorization: `OAuth ${headerParams}`
    }

    //オプションを定義
    const options = {
      url: this.getRequestTokenUrl,
      headers: header
    }
    //リクエスト送信
    return await this.getTokenSync(options)
  }

  async getAccessToken(params) {
    const tmpParams = {}
    Object.keys(params).forEach((item) => {
      tmpParams[`${item}`] = encodeURIComponent(params[`${item}`])
    })

    const requestParams = Object.keys(tmpParams).map((item) => {
      return `${item}=${tmpParams[`${item}`]}`
    }).sort((a, b) => {
      if (a < b) return -1
      if (a > b) return 1
      return 0
    }).join('&')

    const dataOfSign = encodeURIComponent('POST') + '&' + encodeURIComponent(this.getAccessTokenUrl) + '&' + encodeURIComponent(requestParams)
    const signature = crypto.createHmac('sha1', this.keyOfSign).update(dataOfSign).digest('base64')

    tmpParams['oauth_signature'] = encodeURIComponent(signature)

    const headerParams = Object.keys(tmpParams).map((item) => {
      return `${item}=${tmpParams[item]}`
    }).join(',')

    const header = {
      Authorization: `OAuth ${headerParams}`
    }

    //オプションを定義
    const options = {
      url: this.getAccessTokenUrl,
      headers: header
    }
    //リクエスト送信
    return await this.getTokenSync(options)
  }

  async getTokenSync(options){
    const axiosCreate = axios.create({
      headers: options.headers
    })
    return await axiosCreate.post(options.url)
      .then((res) => {
        const resData = querystring.parse(res.data)
        const tmpData = {
          oauth_token: resData.oauth_token,
          oauth_token_secret: resData.oauth_token_secret,
        }
        return tmpData
      }).catch((err) => {
        throw err
      })
  }
}
