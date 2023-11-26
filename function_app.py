import logging
import azure.functions as func
import os
import base64
import re
import json
import hashlib
import redis
from openai import AzureOpenAI
import random
from requests.auth import AuthBase, HTTPBasicAuth
from requests_oauthlib import OAuth2Session, TokenUpdated
import requests
from flask import Flask, request, redirect, session, url_for, render_template

app = func.FunctionApp()

r = redis.StrictRedis(host='twitterbot.redis.cache.windows.net', port=6380, db=0, password=os.environ.get("REDIS_PASSWORD"), ssl=True)

openai = AzureOpenAI(
    api_key = os.environ.get("OPENAPI_KEY"),
    api_version = '2023-03-15-preview', # this may change in the future
    azure_endpoint= os.environ.get("OPENAPI_ENDPOINT"), # your endpoint should look like the following https://YOUR_RESOURCE_NAME.openai.azure.com/
)

# openai.api_key = os.environ.get("OPENAPI_KEY")
# openai.api_base = os.environ.get("OPENAPI_ENDPOINT") # your endpoint should look like the following https://YOUR_RESOURCE_NAME.openai.azure.com/
# openai.api_type = 'azure'
# openai.api_version = '2023-03-15-preview' # this may change in the future

chatgpt_model_name=os.environ.get("MODEL_NAME") #This will correspond to the custom name you chose for your deployment when you deployed a model. 

twitter_client_id = os.environ.get("TWITTER_CLIENT_ID")
twitter_client_secret = os.environ.get("TWITTER_CLIENT_SECRET")
auth_url = "https://twitter.com/i/oauth2/authorize"
token_url = "https://api.twitter.com/2/oauth2/token"
redirect_uri = os.environ.get("REDIRECT_URI")
scopes = ["tweet.read", "users.read", "tweet.write", "offline.access"]

code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
code_challenge = code_challenge.replace("=", "")

@app.schedule(schedule="0 */3 * * *", arg_name="myTimer", run_on_startup=True,
              use_monitor=False) 
def twitter_automation(myTimer: func.TimerRequest) -> None:
    if myTimer.past_due:
        logging.info('The timer is past due!')

    logging.info('calling the refresh twitter token function')
    refreshed_token = getTwitterToken()
    logging.info('calling the gpt service to create tweet')
    tweet = callGPT()
    tweet = tweet.replace('"',"")
    payload = {"text": "{}".format(tweet)}
    logging.info('creating the tweet')
    post_tweet(payload = payload, token=refreshed_token)
    logging.info('Python timer trigger function executed.')

def make_token():
    return OAuth2Session(twitter_client_id, redirect_uri=redirect_uri, scope=scopes)

def post_tweet(payload, token):
    print("Tweeting!")
    return requests.request(
        "POST",
        "https://api.twitter.com/2/tweets",
        json=payload,
        headers={
            "Authorization": "Bearer {}".format(token["access_token"]),
            "Content-Type": "application/json",
        },
    )

def getTwitterToken():
    twitter_token = r.get("token")
    bb_t = twitter_token.decode("utf8").replace("'", '"')
    data = json.loads(bb_t)
    twitter = make_token()
    refreshed_token = twitter.refresh_token(
        client_id=twitter_client_id,
        client_secret=twitter_client_secret,
        token_url=token_url,
        refresh_token=data["refresh_token"],
        )
    st_refreshed_token = '"{}"'.format(refreshed_token)
    j_refreshed_token = json.loads(st_refreshed_token)
    r.set("token", j_refreshed_token)
    return refreshed_token

def callGPT():
    topic = getTopic()
    question = f"What are the top trending keywords in {topic}. Please give keywords only '/' seperated and no extra text"
    print(question)
    # Send a completion call to generate an answer
    response = openai.chat.completions.create(
                    model=chatgpt_model_name,
                    messages=[
                            {"role": "system", "content": "You are a helpful assistant."},
                            {"role": "user", "content": question}
                        ]
                    )
    logging.info(response)
    keywords = response.choices[0].message.content
    keywordsList = keywords.split('/')
    print(keywordsList)
    emotion = getEmotion()
    tweetMessageString = f"Make a {emotion} tweet on " + random.choice(keywordsList)
    print(tweetMessageString)
    tweetResponse = openai.chat.completions.create(
                    model=chatgpt_model_name,
                    messages=[
                            {"role": "system", "content": "You are a helpful assistant."},
                            {"role": "user", "content": tweetMessageString}
                        ]
                        ,max_tokens=200
                    )
    
    print(tweetResponse.choices[0].message.content)
    return tweetResponse.choices[0].message.content

def getEmotion():
    emotion = ['happy', 'sad', 'funny', 'excited', 'lazy', 'anxiety', 'suprise']
    return random.choice(emotion)

def getTopic():
    topics = ['books', 'technology', 'movies', 'hollywood', 'tv shows', 'cartoons', 'games', 'life', 'socrates', 'philosophy', 'songs', 'art', 'artist', 'jokes']
    return random.choice(topics)