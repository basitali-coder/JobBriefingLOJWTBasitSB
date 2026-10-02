//Verion 2.0
//Change to MMO envirment principles
//env is being passed in from cloud flare with attributes from settings such as privateKeyPem

//////////////Please review the below when changing any environment////////////
///Start//

/*
Salesforce org related vars
*/
const SF_DOMAIN = "https://masternaut--basit.sandbox.my.salesforce.com";
const CLIENT_ID ="3MVG97IVyarqycDnBbiu2NuL9tISYp12KdkLGfm_qFZ6A9sAfokVo9BknrcvsKpxqJwsooCiwLObf0XIuJmHh"; //External App
const LIGHTNING_OUT_APP_ID = "1Usbh00000000o1CAA";

//Would be repalced by MMO domain
//This should be also added as CORS and trusted URL in salesforce org
//Same should be set in salesforce external app redirect/callback
//This domain URL must be in trusted URL and CORS in salesforce org
const ALLOWED_ORIGIN = "https://basitali-coder.github.io"; 


//Key related vars
//Might change or not used for actual MMO key
const KEY_START_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
const KEY_END_HEADER = "-----END RSA PRIVATE KEY-----";

///End//
////////////////////////////////////////////////////////////

function corsHeaders() {
    return {"Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Vary": "Origin"};
}


function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data),{status,headers: {"Content-Type": "application/json",...corsHeaders()}});
}


/*
 * Base64URL encoding
 */
function base64UrlEncode(data) {
    let bytes;
    if (typeof data === "string") {
        bytes = new TextEncoder().encode(data);
    } else {
        bytes = new Uint8Array(data);
    }

    let binary = "";
    bytes.forEach(byte => binary += String.fromCharCode(byte));

    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}


//For cloud flare  RSA private key has been set to JWT_PRIVATE_KEY environment variable which is set implicitly by cloud flare
//  i.e
//        const privateKeyPem =  env.JWT_PRIVATE_KEY;
//So no assignment is required for privateKeyPem 
// For different backend use its approach
// perhaps encription is required as below


async function importPrivateKey(privateKeyPem) {
    const pemContents = privateKeyPem.replace(KEY_START_HEADER, "").replace(KEY_END_HEADER, "").replace(/\s/g, "");
    const binary = Uint8Array.from( atob(pemContents), c => c.charCodeAt(0));
    return crypto.subtle.importKey("pkcs8", binary.buffer,{ name: "RSASSA-PKCS1-v1_5",
                                                            hash: "SHA-256"}, 
                                                          false, ["sign"]);
}

/*
 *  Create Salesforce JWT
    Doc: https://help.salesforce.com/s/articleView?id=mktg.dato_getstarted_token_api_jwt.htm&type=5
 */
async function createJWT(username, privateKeyPem) {
    const now = Math.floor(Date.now()/1000);
    const header = {alg: "RS256",typ: "JWT"};
    const payload = {   iss: CLIENT_ID,
                        sub: username,
                        aud: SF_DOMAIN,
                        exp: now + 180
                    };

    const encodedHeader = base64UrlEncode( JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const unsignedToken = encodedHeader +"." + encodedPayload;

    const privateKey = await importPrivateKey(privateKeyPem);
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(unsignedToken));

    return (unsignedToken +"." +base64UrlEncode(signature));
}


/*
 * Salesforce JWT login
 */
async function getSalesforceToken(username, privateKeyPem) {

    const assertion = await createJWT( username, privateKeyPem);

    const response =await fetch(SF_DOMAIN +"/services/oauth2/token",
                                { method: "POST",
                                headers: {"Content-Type":"application/x-www-form-urlencoded"},
                                    body:new URLSearchParams({grant_type:"urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                            assertion:assertion})
                                });

    const text =await response.text();

    let result;

    try {
        result = JSON.parse(text);
    }
    catch { result = {  raw: text};
    }

    if (!response.ok) {
        return {success: false, status: response.status,error: result};
    }
    return {success: true,token: result};
}


/*
 * Get Lightning Out Frontdoor URL
 * 
 */
async function getFrontdoor(accessToken) {
    const response =    await fetch(SF_DOMAIN +"/services/oauth2/lightningoutsingleaccess",
                                    {method: "POST",
                                    headers: {"Authorization":"Bearer " + accessToken, "Content-Type":"application/json"},
                                    body:JSON.stringify({ appId:LIGHTNING_OUT_APP_ID})
                                    }
        );

    const text = await response.text();

    let result;

    try {
        result = JSON.parse(text);
    }
    catch {
        result = {raw: text};
    }

    return {ok: response.ok, status: response.status,result};
}

//Note: env get secret by cloud flare in this scenerio for MMO please only use backend approach.
export default {

    async fetch(request, env){
        /*
         * CORS
         */
        if (request.method === "OPTIONS") {
            return new Response(null,{status: 204,headers: corsHeaders()});
        }

        /*
         * Only POST 
         * Depending on implementation or can be removed
         */

        if (request.method !== "POST") {
            return jsonResponse({ error:"Only POST allowed" }, 405 );
        }

        try {
            const url = new URL(request.url);
            const path =url.pathname.replace(/^\/+|\/+$/g, "");
            const body = await request.json();

            //LOGIN
            if (path === "login") {

                const username = body.username;


                if (!username) {
                    return jsonResponse({error:"missing username"},400);
                }


                /*
                 * Generate JWT and authenticate
                 * against Salesforce.
                 */

                const login =await getSalesforceToken(username, env.JWT_PRIVATE_KEY);
                if (!login.success) {
                    return jsonResponse(login,login.status);
                }

                const accessToken = login.token.access_token;

                /*
                 * Get Lightning Out frontdoor.
                 */

                const frontdoor =await getFrontdoor(accessToken);
                if (!frontdoor.ok) {
                    return jsonResponse({error:"Unable to create Lightning Out frontdoor",
                                        salesforce:frontdoor.result
                                        },
                                        frontdoor.status);
                }


                /*
                 * Please Do NOT return the Salesforce
                 * access token to the frontend.
                 *
                 * Return only the frontdoor URL.
                 */
                return jsonResponse({success:true, frontdoor_uri:frontdoor.result.frontdoor_uri});
            }

            return jsonResponse({error:"Unknown endpoint",
                                receivedPath:url.pathname,
                                hint:"Expected /login"
                                },404);

        }
        catch (error){
                        return jsonResponse({error:error.message},500);
                     }
    }
};
