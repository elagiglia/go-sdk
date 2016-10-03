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
*/

package main

import (
    "github.com/mercadolibre/sdk"
    "github.com/gorilla/mux"
    "fmt"
    "log"
    "io/ioutil"
    "net/http"
    "sync"
    "strings"
    "bytes"
)

const (
    CLIENT_ID = 2016679662291617
    CLIENT_SECRET = "bA89yqE9lPeXwcZkOLBTdKGDXYFbApuZ"
    HOST = "http://localhost:8080"
)

var userCode map[string] string
var userCodeMutex sync.Mutex

func main() {


    userCode = make(map[string] string)

    log.Fatal(http.ListenAndServe(":8080", getRouter()))

     /* Example 4)
      This example shows you how to PUT a change in an Item.*/


    /*change := "{\"available_quantity\": 6}"

    resp, err = client.Put("/items/" + item.Id, &change)

    if err != nil {
        log.Printf("Error %s\n", err.Error())
    }
    userInfo, _ = ioutil.ReadAll(resp.Body)
    resp.Body.Close()

    fmt.Printf("Example 4) \n\t Response of PUT /items : %s\n", userInfo)


   *//*  Example 5)
     This example shows you how to DELETE an Item.*//*


    resp, err = client.Delete("/items/" + item.Id)

    if err != nil {
        log.Printf("Error %s\n", err.Error())
    }
    userInfo, _= ioutil.ReadAll(resp.Body)
    resp.Body.Close()

    fmt.Printf("Example 5 \n\t Response of DELETE /items : %s\n", userInfo)*/
}

type item struct {
    Id string
}



type Route struct {
    Name        string
    Method      string
    Pattern     string
    HandlerFunc http.HandlerFunc
}

type Routes []Route



func getRouter() *mux.Router{

    routes := Routes{

        Route{
            "item",
            "GET",
            "/{userId}/items/{itemId}",
            getItem,
        },
        Route{
            "item",
            "POST",
            "/{userId}/items/{itemId}",
            postItem,
        },
        Route{
            "sites",
            "GET",
            "/{userId}/sites",
            getSites,
        },
        Route{
            "me",
            "GET",
            "/{userId}/users/me",
            me,
        },
        Route{
            "index",
            "GET",
            "/",
            returnLinks,
        },
    }
    router := mux.NewRouter();

    for _, route := range routes {
        var handler http.Handler

        handler = route.HandlerFunc

        router.
        Methods(route.Method).
        Path(route.Pattern).
        Name(route.Name).
        Handler(handler)

    }

    return router
}

const USER_ID = "userId"
const ITEM_ID = "itemId"

func getItem(w http.ResponseWriter, r *http.Request) {


    user := getParam(r, USER_ID)
    productId := getParam(r, ITEM_ID)

    code := getUserCode(r)

    client, err := sdk.NewClient(CLIENT_ID, code, CLIENT_SECRET, HOST + "/" + user + "/items/" + productId)

    response, err := client.Get("/items/" + productId)

    if err != nil {
        log.Printf("Error: ", err)
        return
    }

    body, _ := ioutil.ReadAll(response.Body)

    fmt.Fprintf(w, "%s", body)
}

/*
This example shows you how to POST (publish) a new Item.
*/

func postItem(w http.ResponseWriter, r *http.Request) {


    user := getParam(r, USER_ID)
    productId := getParam(r, ITEM_ID)

    code := getUserCode(r)

    client, err := sdk.NewClient(CLIENT_ID, code, CLIENT_SECRET, HOST + "/" + user + "/items/" + productId)

    item := "{\"title\":\"Item de test - No Ofertar\",\"category_id\":\"MLA1912\",\"price\":10,\"currency_id\":\"ARS\",\"available_quantity\":1,\"buying_mode\":\"buy_it_now\",\"listing_type_id\":\"bronze\",\"condition\":\"new\",\"description\": \"Item:,  Ray-Ban WAYFARER Gloss Black RB2140 901  Model: RB2140. Size: 50mm. Name: WAYFARER. Color: Gloss Black. Includes Ray-Ban Carrying Case and Cleaning Cloth. New in Box\",\"video_id\": \"YOUTUBE_ID_HERE\",\"warranty\": \"12 months by Ray Ban\",\"pictures\":[{\"source\":\"http://upload.wikimedia.org/wikipedia/commons/f/fd/Ray_Ban_Original_Wayfarer.jpg\"},{\"source\":\"http://en.wikipedia.org/wiki/File:Teashades.gif\"}]}"

    response, err := client.Post("/items/", item)

    if err != nil {
        log.Printf("Error: ", err)
        return
    }

    body, _ := ioutil.ReadAll(response.Body)

    fmt.Fprintf(w, "%s", body)
}

func getSites(w http.ResponseWriter, r *http.Request) {

    user := getParam(r, USER_ID)
    code := getUserCode(r)

    client, err := sdk.NewClient(CLIENT_ID, code, CLIENT_SECRET, HOST + "/" + user + "/sites")

    response, err := client.Get("/sites")

    log.Printf("client mem address: %p", client)
    if err != nil {
        log.Printf("Error: ", err)
        return
    }

    body, _ := ioutil.ReadAll(response.Body)

    fmt.Fprintf(w, "%s", body)
}

func me(w http.ResponseWriter, r *http.Request) {

    user := getParam(r, USER_ID)
    code := getUserCode(r)

    client, err := sdk.NewClient(CLIENT_ID, code, CLIENT_SECRET, HOST + "/" + user + "/users/me")

    if err != nil {
        log.Printf("Error: ", err.Error())
        return
    }

    response, err := client.Get("/users/me")

    if err != nil {
        log.Printf("Error: ", err.Error())
        return
    }

    body, _ := ioutil.ReadAll(response.Body)

    /*Example
      If the API to be called needs authorization and authentication (private api), the the authentication URL needs to be generated.
      Once you generate the URL and call it, you will be redirected to a ML login page where your credentials will be asked. Then, after
      entering your credentials you will obtained a CODE which will be used to get all the authorization tokens.
    */
    if response.StatusCode == http.StatusForbidden {

        url := sdk.GetAuthURL(CLIENT_ID, sdk.MLA, HOST + "/" + user + "/users/me")
        log.Printf("Returning Authentication URL:%s\n", url)
        http.Redirect(w, r, url, 301)

    }

    fmt.Fprintf(w, "%s", body)
}


func getUserCode(r *http.Request) string {

    user := getParam(r, USER_ID)
    code := r.FormValue("code")

    userCodeMutex.Lock()
    defer userCodeMutex.Unlock()

    if strings.Compare(code, "") == 0 {
        code = userCode[user]
    }else {
        userCode[user] = code
    }

    return code
}

func getParam(r *http.Request, param string) string {

    pathParams := mux.Vars(r)
    value :=  pathParams[param]

    if strings.Compare(value, "") == 0 {
        log.Printf("%s is missing", param)
    }

    return value
}

func returnLinks(w http.ResponseWriter, r *http.Request) {

    userId := "/123"
    href := "href=" + HOST  + userId

    var links bytes.Buffer
    links.WriteString("<a " + href + "/items/MLU439286635>" + HOST + "/items/MLU439286635</a><br>")
    links.WriteString("<a " + href + "/sites>" + HOST + "/sites</a><br>")
    links.WriteString("<a " + href + "/users/me>" + HOST + "/users/me</a><br>")


    fmt.Fprintf(w, "%s", links.String())
}