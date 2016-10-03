/*
Copyright [2016] [mercadolibre.com]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


**

This package allows you to interact with the Mercadolibre open platform API.
The are two main structures:
1) Client
2) Authorization

1) - This structure keeps within the secret to be used for generating the token to be sent when calling to the private APIs.
     This also provides several methods to call either public and private APIs

2) - This structure keeps the tokens and their expiration time and has to be passed by param each time a call has to be performed to any private API.
*/

package sdk

import (
    "net/url"
    "strconv"
    "bytes"
    "net/http"
    "io"
    "encoding/json"
    "io/ioutil"
    "log"
    "strings"
    "errors"
    "time"
    "sync"
)

const (

    MLA = "https://auth.mercadolibre.com.ar" // Argentina
    MLB = "https://auth.mercadolivre.com.br" // Brasil
    MCO = "https://auth.mercadolibre.com.co" // Colombia
    MCR = "https://auth.mercadolibre.com.cr" // Costa Rica
    MEC = "https://auth.mercadolibre.com.ec" // Ecuador
    MLC = "https://auth.mercadolibre.cl"      // Chile
    MLM = "https://auth.mercadolibre.com.mx" // Mexico
    MLU = "https://auth.mercadolibre.com.uy" // Uruguay
    MLV = "https://auth.mercadolibre.com.ve" // Venezuela
    MPA = "https://auth.mercadolibre.com.pa" // Panama
    MPE = "https://auth.mercadolibre.com.pe" // Peru
    MPT = "https://auth.mercadolivre.pt"      // Portugal
    MRD = "https://auth.mercadolibre.com.do" // Dominicana

    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    API_URL = "https://api.mercadolibre.com"
)

type refreshToken func (*Client) error

var refreshTok refreshToken
var publicClient = &Client{apiUrl:API_URL, auth:ANONYMOUS}
var clientByUser map[string] *Client
var clientByUserMutex sync.Mutex
var ANONYMOUS = Authorization{}
var authMutex = &sync.Mutex{}

var dbg Debug

func init() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    clientByUser = make(map[string] *Client)
    refreshTok = hookRefreshToken
    //dbg = true
}


type Client struct {
    apiUrl      string
    id          int64
    secret      string
    code        string
    redirectUrl string
    auth        Authorization
    httpClient  HttpClient
}

/*
This function returns the URL to be used for user authentication and authorization
 */
func GetAuthURL(clientId int64, base_site, callback string) string {

    authURL := newAuthorizationURL(base_site  + "/authorization")
    authURL.addResponseType("code")
    authURL.addClientId(clientId)
    authURL.addRedirectUri(callback)

    return authURL.string()
}

/*
This method returns a Client which can be used to call mercadolibre private API
client id, code and secret are generated when creating your application

*/
func GetPrivateApiClient(id int64, code string, secret string, redirectUrl string) (*Client, error) {

    clientByUserMutex.Lock()
    defer clientByUserMutex.Unlock()

    key := strconv.FormatInt(id, 10) + code

    var client *Client

    client = clientByUser[key]

    if client == nil {
        client = &Client{id:id, code:code, secret:secret, redirectUrl:redirectUrl, apiUrl:API_URL, httpClient:MeliHttpClient{}}
        clientByUser[key] = client
        dbg.Printf("Building a client: %p for clientid:%d code:%s\n", client, id, code)
    }

    auth, err := client.authorize()

    if err != nil {
        return nil, err
    }

    client.auth = *auth

    return client, nil
}

/*
This client may be used to access public API which does not need authorization
*/
func GetPublicApiClient() (*Client, error) {

    return publicClient, nil
}

/*
This method returns an Authorization object which contains the needed tokens
to interact with ML API
 */
func (client *Client) authorize() (*Authorization, error) {

    authURL := newAuthorizationURL(client.apiUrl + "/oauth/token")
    authURL.addGrantType(AUTHORIZATION_CODE)
    authURL.addClientId(client.id)
    authURL.addClientSecret(client.secret)
    authURL.addCode(client.code)
    authURL.addRedirectUri(client.redirectUrl)

    resp, err := client.httpClient.Post(authURL.string(), "application/json", *(new(io.Reader)))

    if err != nil {
        dbg.Printf("Error when posting: %s", err)
        return nil, err
    }

    if resp.StatusCode != http.StatusOK {
        return nil, errors.New("There was an error while authorizing. Check wether your code has not expired.")
    }

    body, err := ioutil.ReadAll(resp.Body)
    resp.Body.Close()

    authorization := new(Authorization)
    if err := json.Unmarshal(body, authorization); err != nil {
        dbg.Printf("Error while receiving the authorization %s %s", err.Error(), body)
        return nil, err
    }

    authorization.ReceivedAt = time.Now().Unix()
    return authorization, nil
}


//HTTP Methods
func (client *Client) Get(resourcePath string) (*http.Response, error) {

    apiUrl, err := client.getAuthorizedURL(resourcePath)

    if err != nil {
        dbg.Printf("Error while refreshing token")
        return nil, err
    }

    resp, err := client.httpClient.Get(apiUrl.string())

    if err != nil {
        dbg.Printf("Error while calling url: %s \n Error: %s", apiUrl.string(), err)
        return nil, err
    }

    return resp, err
}

func (client *Client) Post(resourcePath string, body string) (*http.Response, error){

    apiUrl, err := client.getAuthorizedURL(resourcePath)

    if err != nil {
        dbg.Printf("Error while refreshing token")
        return nil, err
    }

    resp, err := client.httpClient.Post(apiUrl.string(), "application/json", bytes.NewReader([]byte(body)))

    if err != nil {
        dbg.Printf("Error while calling url: %s \n Error: %s", apiUrl.string(), err)
        return nil, err
    }

    return resp, nil
}

func (client *Client) Put(resourcePath string, body *string) (*http.Response, error){

    apiUrl, err := client.getAuthorizedURL(resourcePath)

    if err != nil {
        dbg.Printf("Error while refreshing token")
        return nil, err
    }

    resp, err := client.httpClient.Put(apiUrl.string(), strings.NewReader(*body))


    return resp, err
}

func (client *Client) Delete(resourcePath string ) (*http.Response, error) {

    apiUrl, err := client.getAuthorizedURL(resourcePath)

    if err != nil {
        dbg.Printf("Error while refreshing token")
        return nil, err
    }

    resp, err := client.httpClient.Delete(apiUrl.string(), nil)

    return resp, nil
}

//This method has side effects. Alters the token that is within the client.
func hookRefreshToken(client *Client) error {

    authorizationURL := newAuthorizationURL(client.apiUrl + "/oauth/token")
    authorizationURL.addGrantType(REFRESH_TOKEN)
    authorizationURL.addClientId(client.id)
    authorizationURL.addClientSecret(client.secret)
    authorizationURL.addRefreshToken(client.auth.RefreshToken)

    resp, err := client.httpClient.Post(authorizationURL.string(), "application/json", *(new(io.Reader)))

    if err != nil {
        dbg.Printf("Error while refreshing token: %s\n", err.Error())
        return err
    }

    if resp.StatusCode != http.StatusOK {
        return errors.New("Refreshing token returned status code " + resp.Status)
    }

    body, err := ioutil.ReadAll(resp.Body)
    resp.Body.Close()

    if err := json.Unmarshal(body, &(client.auth)); err != nil {
        dbg.Printf("Error while receiving the authorization %s %s", err.Error(), body)
        return err
    }

    client.auth.ReceivedAt = time.Now().Unix()

    dbg.Printf("auth received at: %d expires in:%d\n", client.auth.ReceivedAt, client.auth.ExpiresIn)
    return nil
}
/*
This method returns the URL + Token to be used by each HTTP request.
If Token needs to be refreshed, then this method will send a POST to ML API to refresh it.
 */
func (client *Client) getAuthorizedURL(resourcePath string) (*AuthorizationURL, error){

    finalUrl := newAuthorizationURL(client.apiUrl + resourcePath)
    var err error

    if client.auth != ANONYMOUS {

        authMutex.Lock()

       if client.auth.isExpired() {
            dbg.Printf("token has expired....refreshing...\n")
            err := refreshTok(client)

            if err != nil {
                dbg.Printf("Error while refreshing token %s\n", err.Error())
                return nil, err
            }
       }

        authMutex.Unlock()
        finalUrl.addAccessToken(client.auth.AccessToken)
    }

    return finalUrl, err
}

type Authorization struct {
    AccessToken  string  `json:"access_token"`
    TokenType    string  `json:"token_type"`
    ExpiresIn    int16   `json:"expires_in"`
    ReceivedAt   int64
    RefreshToken string  `json:"refresh_token"`
    Scope        string  `json:"scope"`
}

func (auth Authorization) isExpired() bool {
    dbg.Printf("received at:%d expires in: %d\n", auth.ReceivedAt, auth.ExpiresIn)
    return ((auth.ReceivedAt + int64(auth.ExpiresIn)) <= (time.Now().Unix() + 60))
}


type Debug bool

func (d Debug) Printf(s string, a ...interface{}) {
    if d {
        log.Printf(s, a...)
    }
}

/*
This struct allows adding all the params needed to the URL to be sent
to the ML API
*/
type AuthorizationURL struct{
    url bytes.Buffer
}

func (u *AuthorizationURL) addGrantType(value string) {
    u.add("grant_type=" + value)
}

func (u *AuthorizationURL) addClientId(value int64) {
    u.add("client_id=" + strconv.FormatInt(value, 10))
}

func (u *AuthorizationURL) addClientSecret(value string) {
    u.add("client_secret=" + url.QueryEscape(value))
}

func (u *AuthorizationURL) addCode(value string) {
    u.add("code=" + url.QueryEscape(value))
}

func (u *AuthorizationURL) addRedirectUri(uri string) {
    u.add("redirect_uri=" + url.QueryEscape(uri))
}

func (u *AuthorizationURL) addRefreshToken(t string) {
    u.add("refresh_token=" + url.QueryEscape(t))
}

func (u *AuthorizationURL) addResponseType(value string) {
    u.add("response_type=" + url.QueryEscape(value))
}

func (u *AuthorizationURL) addAccessToken(t string){
    u.add("access_token=" + url.QueryEscape(t))
}

func (u *AuthorizationURL) string() string {
    return u.url.String()
}

func (u *AuthorizationURL) add(value string) {

    if !strings.Contains(u.url.String(), "?"){
        u.url.WriteString("?" + value)
    } else if strings.LastIndex("&",u.url.String()) >= u.url.Len(){
        u.url.WriteString(value)
    } else {
        u.url.WriteString("&" + value)
    }
}

func newAuthorizationURL(baseURL string) *AuthorizationURL{
    authURL := new(AuthorizationURL)
    authURL.url.WriteString(baseURL)
    return authURL
}



type HttpClient interface {
    Get(url string) (*http.Response, error)
    Post(url string, bodyType string, body io.Reader) (*http.Response, error)
    Put(url string, body io.Reader) (*http.Response, error)
    Delete(url string, body io.Reader) (*http.Response, error)
}

type MeliHttpClient struct {

}

func (httpClient MeliHttpClient) Get(url string) (*http.Response, error){

    resp, err := http.Get(url)

    if err != nil {
        dbg.Printf("Error while calling url: %s \n Error: %s", url, err)
        return nil, err
    }

    return resp, nil
}


func (httpClient MeliHttpClient) Post(url string, bodyType string, body io.Reader) (*http.Response, error) {

    resp, err := http.Post(url, bodyType, body)

    if err != nil {
        dbg.Printf("Error while calling url: %s \n Error: %s", url, err)
        return nil, err
    }

    return resp, nil
}

func (httpClient MeliHttpClient) Put(url string, body io.Reader) (*http.Response, error){

    return httpClient.executeHttpRequest(http.MethodPut, url, body)
}

func (httpClient MeliHttpClient) Delete(url string, body io.Reader) (*http.Response, error){

    return httpClient.executeHttpRequest(http.MethodDelete, url, body)

}

func (httpClient MeliHttpClient) executeHttpRequest(method string, url string, body io.Reader) (*http.Response, error) {

    req, err := http.NewRequest(method, url, body)

    if err != nil {
        dbg.Printf("Error when creating %s request %d.", http.MethodDelete, err)
        return nil, err
    }

    resp, err := http.DefaultClient.Do(req)

    if err != nil {
        dbg.Printf("Error while calling url: %s\n Error: %s", url, err)
        return nil, err
    }

    return resp, nil
}