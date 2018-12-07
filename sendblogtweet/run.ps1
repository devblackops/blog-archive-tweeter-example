
function Get-ShortUrl {
    <#
    .SYNOPSIS
    Create a new Bit.Ly link
    .EXAMPLE
    PS> Get-ShortUrl -Url 'www.google.com' -OAuthToken = '12345'
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        $Url,

        [parameter(Mandatory)]
        [string]$OAuthToken
    )

    $ErrorActionPreference = 'Stop'

    $headers = @{
        Authorization = "Bearer $OAuthToken"
    }

    $body = @{long_url = $Url} | ConvertTo-Json

    $params = @{
        Uri         = 'https://api-ssl.bitly.com/v4/shorten'
        Method      = 'Post'
        Body        = $body
        Headers     = $headers
        ContentType = 'application/json'
    }
    (Invoke-RestMethod @params).link
}

# https://github.com/MeshkDevs/InvokeTwitterAPIs
function Get-OAuth {
    <#
    .SYNOPSIS
    This function creates the authorization string needed to send a POST or GET message to the Twitter API
    .PARAMETER AuthorizationParams
    This hashtable should the following key value pairs
    HttpEndPoint - the twitter resource url [Can be found here: https://dev.twitter.com/rest/public]
    RESTVerb - Either 'GET' or 'POST' depending on the action
    Params - A hashtable containing the rest parameters (key value pairs) associated that method
    OAuthSettings - A hashtable that must contain only the following keys and their values (Generate here: https://dev.twitter.com/oauth)
                ApiKey
                ApiSecret
                AccessToken
                AccessTokenSecret
    .LINK
    This function evolved from code found in Adam Betram's Get-OAuthAuthorization function in his MyTwitter module.
    The MyTwitter module can be found here: https://gallery.technet.microsoft.com/scriptcenter/Tweet-and-send-Twitter-DMs-8c2d6f0a
    Adam Betram's blogpost here: http://www.adamtheautomator.com/twitter-powershell/ provides a detailed explanation
    about how to generate an access token needed to create the authorization string

    .EXAMPLE
    $OAuth = @{'ApiKey' = 'yourapikey'; 'ApiSecret' = 'yourapisecretkey';'AccessToken' = 'yourapiaccesstoken';'AccessTokenSecret' = 'yourapitokensecret'}
    $Parameters = @{'q'='rumi'}
    $AuthParams = @{}
    $AuthParams.Add('HttpEndPoint', 'https://api.twitter.com/1.1/search/tweets.json')
    $AuthParams.Add('RESTVerb', 'GET')
    $AuthParams.Add('Params', $Parameters)
    $AuthParams.Add('OAuthSettings', $OAuth)
    $AuthorizationString = Get-OAuth -AuthorizationParams $AuthParams
    #>
    [OutputType('System.Management.Automation.PSCustomObject')]
    Param($AuthorizationParams)
    process {
        try {
            ## Generate a random 32-byte string. I'm using the current time (in seconds) and appending 5 chars to the end to get to 32 bytes
            ## Base64 allows for an '=' but Twitter does not.  If this is found, replace it with some alphanumeric character
            $OauthNonce = [System.Convert]::ToBase64String(([System.Text.Encoding]::ASCII.GetBytes("$([System.DateTime]::Now.Ticks.ToString())12345"))).Replace('=', 'g')
            ## Find the total seconds since 1/1/1970 (epoch time)
            $EpochTimeNow = [System.DateTime]::UtcNow - [System.DateTime]::ParseExact('01/01/1970', "dd'/'MM'/'yyyy", $null)
            $OauthTimestamp = [System.Convert]::ToInt64($EpochTimeNow.TotalSeconds).ToString()
            ## Build the signature
            $SignatureBase = "$([System.Uri]::EscapeDataString($AuthorizationParams.HttpEndPoint))&"
            $SignatureParams = @{
                'oauth_consumer_key'     = $AuthorizationParams.OAuthSettings.ApiKey
                'oauth_nonce'            = $OauthNonce
                'oauth_signature_method' = 'HMAC-SHA1'
                'oauth_timestamp'        = $OauthTimestamp
                'oauth_token'            = $AuthorizationParams.OAuthSettings.AccessToken
                'oauth_version'          = '1.0'
            }
            $AuthorizationParams.Params.Keys | ForEach-Object {
                $SignatureParams.Add($_ , [System.Net.WebUtility]::UrlEncode($AuthorizationParams.Params.Item($_)).Replace('+', '%20'))
            }

            ## Create a string called $SignatureBase that joins all URL encoded 'Key=Value' elements with a &
            ## Remove the URL encoded & at the end and prepend the necessary 'POST&' verb to the front
            $SignatureParams.GetEnumerator() | Sort-Object name | ForEach-Object {
                $SignatureBase += [System.Uri]::EscapeDataString("$($_.Key)=$($_.Value)&")
            }

            $SignatureBase = $SignatureBase.Substring(0, $SignatureBase.Length - 1)
            $SignatureBase = $SignatureBase.Substring(0, $SignatureBase.Length - 1)
            $SignatureBase = $SignatureBase.Substring(0, $SignatureBase.Length - 1)
            $SignatureBase = $AuthorizationParams.RESTVerb + '&' + $SignatureBase

            ## Create the hashed string from the base signature
            $SignatureKey = [System.Uri]::EscapeDataString($AuthorizationParams.OAuthSettings.ApiSecret) + '&' + [System.Uri]::EscapeDataString($AuthorizationParams.OAuthSettings.AccessTokenSecret)

            $hmacsha1       = [System.Security.Cryptography.HMACSHA1]::new()
            $hmacsha1.Key   = [System.Text.Encoding]::ASCII.GetBytes($SignatureKey)
            $OauthSignature = [System.Convert]::ToBase64String($hmacsha1.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($SignatureBase)))

            ## Build the authorization headers using most of the signature headers elements.  This is joining all of the 'Key=Value' elements again
            ## and only URL encoding the Values this time while including non-URL encoded double quotes around each value
            $AuthorizationParams = $SignatureParams
            $AuthorizationParams.Add('oauth_signature', $OauthSignature)

            $AuthorizationString = 'OAuth '
            $AuthorizationParams.GetEnumerator() | sort name | ForEach-Object {
                $AuthorizationString += $_.Key + '="' + [System.Uri]::EscapeDataString($_.Value) + '", '
            }
            $AuthorizationString = $AuthorizationString.TrimEnd(', ')
            Write-Verbose "Using authorization string '$AuthorizationString'"
            $AuthorizationString
        }
        catch {
            Write-Error $_.Exception.Message
        }
    }
}

function Invoke-TwitterRestMethod {
    <#
    .SYNOPSIS
    This function sends a POST or GET message to the Twitter API and returns the JSON response.
    .PARAMETER ResourceURL
    The desired twitter resource url [REST APIs can be found here: https://dev.twitter.com/rest/public]

    .PARAMETER RestVerb
    Either 'GET' or 'POST' depending on the resource URL
    .PARAMETER  Parameters
    A hashtable containing the rest parameters (key value pairs) associated that resource url. Pass empty hash if no paramters needed.
    .PARAMETER OAuthSettings
    A hashtable that must contain only the following keys and their values (Generate here: https://dev.twitter.com/oauth)
                ApiKey
                ApiSecret
                AccessToken
                AccessTokenSecret
    .EXAMPLE
    $OAuth = @{'ApiKey' = 'yourapikey'; 'ApiSecret' = 'yourapisecretkey';'AccessToken' = 'yourapiaccesstoken';'AccessTokenSecret' = 'yourapitokensecret'}
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/mentions_timeline.json' -RestVerb 'GET' -Parameters @{} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/user_timeline.json' -RestVerb 'GET' -Parameters @{'count' = '1'} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/home_timeline.json' -RestVerb 'GET' -Parameters @{'count' = '1'} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/retweets_of_me.json' -RestVerb 'GET' -Parameters @{} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/search/tweets.json' -RestVerb 'GET' -Parameters @{'q'='powershell';'count' = '1'}} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/account/settings.json' -RestVerb 'POST' -Parameters @{'lang'='tr'} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/retweets/509457288717819904.json' -RestVerb 'GET' -Parameters @{} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/show.json' -RestVerb 'GET' -Parameters @{'id'='123'} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/destroy/240854986559455234.json' -RestVerb 'GET' -Parameters @{} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/update.json' -RestVerb 'POST' -Parameters @{'status'='@FollowBot'} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/direct_messages.json' -RestVerb 'GET' -Parameters @{} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/direct_messages/destroy.json' -RestVerb 'POST' -Parameters @{'id' = '559298305029844992'} -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/direct_messages/new.json' -RestVerb 'POST' -Parameters @{'text' = 'hello, there'; 'screen_name' = 'ruminaterumi' } -OAuthSettings $OAuth
    $mediaId = Invoke-TwitterMEdiaUpload -MediaFilePath 'C:\Books\pic.png' -ResourceURL 'https://upload.twitter.com/1.1/media/upload.json' -OAuthSettings $OAuth
    Invoke-TwitterRestMethod -ResourceURL 'https://api.twitter.com/1.1/statuses/update.json' -RestVerb 'POST' -Parameters @{'status'='FollowBot'; 'media_ids' = $mediaId } -OAuthSettings $OAuth
    #>
    [CmdletBinding()]
    [OutputType('System.Management.Automation.PSCustomObject')]
    Param(
        [Parameter(Mandatory)]
        [string]$ResourceURL,

        [Parameter(Mandatory)]
        [string]$RestVerb,

        [Parameter(Mandatory)]
        $Parameters,

        [Parameter(Mandatory)]
        $OAuthSettings
    )

    try {
        $baseUrl = 'https://api.twitter.com/1.1/'
        $url = $baseUrl + $ResourceURL
        $authParams = @{
            HttpEndPoint  = $url
            RESTVerb      = $RestVerb
            Params        = $Parameters
            OAuthSettings = $OAuthSettings
        }
        $authString = Get-OAuth -AuthorizationParams $authParams
        if ($Parameters.Count -gt 0) {
            $url = $url + '?'
            $Parameters.Keys | ForEach-Object {
                $url = $url + $_ + '=' + [System.Net.WebUtility]::UrlEncode($Parameters.Item($_)).Replace('+', '%20') + '&'
            }
            $url = $url.Substring(0, $url.Length - 1)
        }
        Invoke-RestMethod -URI $url -Method $RestVerb -Headers @{ 'Authorization' = $authString } -ContentType "application/x-www-form-urlencoded"
    } catch {
        Write-Error $_.Exception.Message
    }
}

$blogFeedUrl = '<YOUR-BLOG-FEED-URL>'

# I don't want these URLs tweeted out as they're not very relevant
$excludedPosts = @()

# Load tracker file
$tracker = Get-Content $inBlob | ConvertFrom-Json
Write-Output "Last tweeted: $($tracker.lastTweetedTime)"

# Get random blog post from feed
$blog           = Invoke-RestMethod -Uri $blogFeedUrl
$candidatePosts = $blog.posts.Where({$_.url -notin $excludedPosts})

# Get a post from the list of available posts that we haven't already tweeted
$tweetedUrls    = $tracker.tweetedPosts | Select-Object -ExpandProperty url
$availablePosts = $candidatePosts.Where({$_.url -notin $tweetedUrls})
$post           = $availablePosts | Get-Random
$availablePosts = $availablePosts.Where({$_.url -ne $post.Url})

if (-not $post) {
    # We've exhausted all available posts so reset
    # the tracker and get a new post from the candidates
    $post                 = $candidatePosts | Get-Random
    $tracker.tweetedPosts = @()
    $availablePosts       = $candidatePosts.Where({$_.url -ne $post.Url})
}

$tracker.candidatePostsCount = $candidatePosts.Count
$tracker.availablePostsCount = $availablePosts.Count

if ($post) {
    $postJson = $post | ConvertTo-Json
    Write-Output "Retrieved post:`n$postJson"

    # Create hashtags
    $hashtags = ''
    $post.tags | Foreach-Object {
        $tag = $_ -replace ' ', ''
        $hashtags += (' #' + $tag)
    }
    $hashtags = $hashtags.Trim()

    # Create tweet text
    $title     = $post.title
    $link      = Get-ShortUrl -Url $post.url -OAuthToken $env:BITLY_OAUTH_TOKEN
    $tweetText = "From the blog archive: $Title`n`n$link`n`n$hashtags"
    Write-Output "Sending tweet:`n$tweetText"
    $oAuth = @{
        ApiKey            = $env:TWITTER_CONSUMER_KEY
        ApiSecret         = $env:TWITTER_CONSUMER_SECRET
        AccessToken       = $env:TWITTER_ACCESS_TOKEN
        AccessTokenSecret = $env:TWITTER_ACCESS_SECRET
    }
    $tweetParams = @{
        ResourceURL   = 'statuses/update.json'
        RestVerb      = 'POST'
        Parameters    = @{
            status = $tweetText
        }
        OAuthSettings = $oAuth
    }
    $tweet     = Invoke-TwitterRestMethod @tweetParams
    $tweetJson = $tweet | ConvertTo-Json
    Write-Output "Tweet sent:`n$tweetJson"

    # Add tweeted post to tracker
    $now = (Get-Date).ToUniversalTime().ToString('u')
    $tracker.lastTweetedTime = $now
    $tweetedPost = @{
        url          = $post.Url
        lastTweeted  = $now
    }
    $tracker.lastTweetedPost     = $tweetedPost
    $tracker.tweetedPosts        += $tweetedPost
    $tracker.tweetedPostCount    = $tracker.tweetedPosts.Count
    $tracker.candidatePostsCount = $candidatePosts.Count
    $tracker.availablePostsCount = $availablePosts.Count
    $trackerJson = $tracker | ConvertTo-Json
    Write-Output "Saving tracker to blob:`n$trackerJson"
    $trackerJson | Out-File -Encoding UTF8 -FilePath $outBlob
}