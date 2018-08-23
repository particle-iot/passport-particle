'use strict';

const BaseStrategy = require('passport-strategy');
const cookie = require('cookie');
const Particle = require('particle-api-js');
const particle = new Particle();

let _options, _verify;

class Strategy extends BaseStrategy {
	constructor(options, verify) {
		super(options, verify);
		_options = options;
		_verify = verify;
		this.name = 'particle';
	}

	authenticate(req) {
		if (req.headers.cookie) {
			const cookies = cookie.parse(req.headers.cookie);
			if (cookies.ember_simple_auth_session) {
				const session = JSON.parse(cookies.ember_simple_auth_session);
				if (session.authenticated) {
					return particle.getUserInfo({
						auth: session.authenticated.access_token
					}).then(response => {
						const usernameFromAPI = response && response.body && response.body.username;

						_verify(session.authenticated, (err, user, info) => {
							const usernameInCookie = user && user.username;

							if (err) {
								return this.error(err);
							}
							if (!user || !usernameFromAPI || usernameInCookie !== usernameFromAPI) {
								return this.fail(info);
							}
							info = {
								accessToken: session.authenticated.access_token,
								refreshToken: session.authenticated.refresh_token,
								trackId: session.authenticated.trackId
							};
							this.success(user, info);
						});
					}, reason => {
						this.fail(reason.shortErrorDescription || reason);
					});
				}

				return this.fail();
			}
		}
		const redirectURL = `${_options.loginURL}?redirect=${_options.callbackURL}`;
		this.redirect(redirectURL);
	}
}

module.exports = { Strategy };
