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
    "encoding/json"
    "io/ioutil"
    "net/http"
    "sync"
    "strings"
)

const (
    CLIENT_CODE = "TG-57ec08ade4b0cd95a48b5297-226470907"
    CLIENT_ID = 396051416295796
    CLIENT_SECRET = "qM66avGpv5rcQxNWF4sno5oH7Cjph0I7"
)

var clientByUser map[string] *sdk.Client
var clientByUserMutex sync.Mutex

func main() {

    clientByUser = make(map[string] *sdk.Client)

    log.Fatal(http.ListenAndServe(":8080", getRouter()))

    /*Example 1)
      Getting the URL to call for authenticating purposes
      Once you generate the URL and call it, you will be redirected to a ML login page where your credentials will be asked. Then, after
      entering your credentials you will obtained a CODE which will be used to get all the authorization tokens.
    */

    url := sdk.GetAuthURL(CLIENT_ID, sdk.MLA, "http://localhost:8080")
    fmt.Printf("Example 1) \n\t Returning Authentication URL:%s\n", url)

    /*
    Example 2)
    Calling a private API example.
    */

    client, err := sdk.NewClient(CLIENT_ID, CLIENT_CODE, CLIENT_SECRET, "https://www.example.com")

    if err != nil {
        log.Printf("Error: %s", err.Error())
        return
    }

    resp, err := client.Get("/users/me")

    if err != nil {
        log.Printf("Error %s\n", err.Error())
    }

    userInfo, _:= ioutil.ReadAll(resp.Body)
    resp.Body.Close()

    fmt.Printf("Example 2) \n \t Response of GET /users/me: %s\n", userInfo)

    /*
      Example 3)
      This example shows you how to POST (publish) a new Item.
     */

    body :=    "{\"title\":\"Item de test - No Ofertar\",\"category_id\":\"MLA1912\",\"price\":10,\"currency_id\":\"ARS\",\"available_quantity\":1,\"buying_mode\":\"buy_it_now\",\"listing_type_id\":\"bronze\",\"condition\":\"new\",\"description\": \"Item:,  Ray-Ban WAYFARER Gloss Black RB2140 901  Model: RB2140. Size: 50mm. Name: WAYFARER. Color: Gloss Black. Includes Ray-Ban Carrying Case and Cleaning Cloth. New in Box\",\"video_id\": \"YOUTUBE_ID_HERE\",\"warranty\": \"12 months by Ray Ban\",\"pictures\":[{\"source\":\"http://upload.wikimedia.org/wikipedia/commons/f/fd/Ray_Ban_Original_Wayfarer.jpg\"},{\"source\":\"http://en.wikipedia.org/wiki/File:Teashades.gif\"}]}"

    resp, err = client.Post("/items", body)

    if err != nil {
        log.Printf("Error %s\n", err.Error())
    }

    itemAsJs, _ := ioutil.ReadAll(resp.Body)
    resp.Body.Close()
    fmt.Printf("Example 3) \n\t Response of POST /items : %s\n", itemAsJs)

    item := new(item)
    err = json.Unmarshal(itemAsJs, item)
    fmt.Printf("ItemId:%s\n", item.Id)

    /*
      Example 4)
      This example shows you how to PUT a change in an Item.
     */

    change := "{\"available_quantity\": 6}"

    resp, err = client.Put("/items/" + item.Id, &change)

    if err != nil {
        log.Printf("Error %s\n", err.Error())
    }
    userInfo, _ = ioutil.ReadAll(resp.Body)
    resp.Body.Close()

    fmt.Printf("Example 4) \n\t Response of PUT /items : %s\n", userInfo)

    /*
     Example 5)
     This example shows you how to DELETE an Item.
    */

   /* resp, err = client.Delete("/items/" + item.Id)

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
            "get_item",
            "GET",
            "/items/{itemId}",
            getItem,
        },/*
        Route{
            "getMyConfig",
            "GET",
            "/users/{id}/myconfig",
            service.handleGetPurchaseById,
        },
        Route{
            "post_purchases",
            "POST",
            "/users/{userid}/purchases",
            service.handlePostPurchases,
        },
        Route{
            "delete_purchase",
            "DELETE",
            "/users/{userid}/purchases/{id}",
            service.handleDeletePurchase,
        },
        Route{
            "get_items_description",
            "GET",
            "/users/{userid}/items",
            service.handleGetItemsDescription,
        },*/
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

const USER_ID = "user_id"

func getItem(w http.ResponseWriter, r *http.Request) {

    user := r.Header.Get(USER_ID)

    if strings.Compare(user, "") == 0 {
        log.Printf("userid is missing")
        return
    }

    pathParams := mux.Vars(r)
    productId := pathParams["itemId"]

    client := getClient(user)

    response, err := client.Get("/items/" + productId)

    if err != nil {
        log.Printf("Error: ", err)
        return
    }

    body, _ := ioutil.ReadAll(response.Body)

    fmt.Fprintf(w, "%s", body)
}


func getClient(user string) *sdk.Client{

    clientByUserMutex.Lock()
    defer clientByUserMutex.Unlock()

    client := clientByUser[user]

    if client == nil {

        client, _ = sdk.NewAnonymousClient()
        clientByUser[user] = client
    }

    return client


}