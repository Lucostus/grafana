package httpclientprovider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"golang.org/x/oauth2"
)

const ForwardedOAuthIdentityMiddlewareName = "forwarded-oauth-identity"

// ForwardedOAuthIdentityMiddleware middleware that sets Authorization/X-ID-Token
// headers on the outgoing request if an OAuth Token is provided
func ForwardedOAuthIdentityMiddleware(token *oauth2.Token) httpclient.Middleware {
	return httpclient.NamedMiddlewareFunc(ForwardedOAuthIdentityMiddlewareName, func(opts httpclient.Options, next http.RoundTripper) http.RoundTripper {
		if token == nil {
			return next
		}
		return httpclient.RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			// TODO: take client secret client id from configuration. add additional property for audience, requested issuer and url. add additional middleware controller for token exchange and
			data := url.Values{
				"client_id":        {"grafana"},
				"client_secret":    {"replace me"},
				"subject_token":    {token.AccessToken},
				"requested_issuer": {"openshift"},
				"audience":         {"grafana"},
				"grant_type":       {"urn:ietf:params:oauth:grant-type:token-exchange"},
			}

			resp, err := http.PostForm("replace me", data)

			if err != nil {
				return next.RoundTrip(req)
			}

			var res map[string]interface{}

			json.NewDecoder(resp.Body).Decode(&res)

			fmt.Println(res["form"])

			req.Header.Set("Authorization", fmt.Sprintf("%s", res["access_token"]))

			idToken, ok := token.Extra("id_token").(string)
			if ok && idToken != "" {
				req.Header.Set("X-ID-Token", idToken)
			}

			return next.RoundTrip(req)
		})
	})
}
