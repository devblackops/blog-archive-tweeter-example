
# Settings
$subscription         = '<YOUR-AZURE-SUBSCRIPTION>'
$resourceGroup        = '<RESOURCE-GROUP-NAME>'
$region               = '<AZURE-REGION>'
$storageAcct          = '<STORAGE-ACCOUNT-NAME>'
$storageContainerName = '<STORAGE-CONTAINER-NAME>'
$functionApp          = '<FUNCTION-APP-NAME>'
$twitterAccessSecret  = '<TWITTER-ACCESS-SECRET>'
$twitterAccessToken   = '<TWITTER-ACCESS-TOKEN>'
$twitterConsumerKey   = '<TWITTER-CONSUMER-KEY>'
$twitterConsumeSecret = '<TWITTER-CONSUMER-SECRET>'
$bitlyOauthToken      = '<BITLY-OAUTH-TOKEN>'

# Login and create resource group
az login
az account set --subscription $subscription
az group create --name $resourceGroup --location $region

# Create storage account and retrieve connection string
az storage account create --resource-group $resourceGroup --name $storageAcct --location $region --sku Standard_LRS
$storageConnStr = az storage account show-connection-string --resource-group $resourceGroup --name $storageAcct --output tsv

# Upload initial empty tracker file
az storage container create --account-name $storageAcct --name $storageContainerName
az storage blob upload --account-name $storageAcct --container-name $storageContainerName --name posts.json --file ./posts.json

# Create a v1 Function app so we can use PowerShell and define settings
az functionapp create --resource-group $resourceGroup --name $functionApp --storage-account $storageAcct --consumption-plan-location $region
az functionapp config appsettings set --resource-group $resourceGroup --name $functionApp --settings "FUNCTIONS_EXTENSION_VERSION = ~1"
az functionapp config appsettings set --resource-group $resourceGroup --name $functionApp --settings "TWITTER_ACCESS_SECRET = $twitterAccessSecret"
az functionapp config appsettings set --resource-group $resourceGroup --name $functionApp --settings "TWITTER_ACCESS_TOKEN = $twitterAccessToken"
az functionapp config appsettings set --resource-group $resourceGroup --name $functionApp --settings "TWITTER_CONSUMER_KEY = $twitterConsumerKey"
az functionapp config appsettings set --resource-group $resourceGroup --name $functionApp --settings "TWITTER_CONSUMER_SECRET = $twitterConsumeSecret"
az functionapp config appsettings set --resource-group $resourceGroup --name $functionApp --settings "BITLY_OAUTH_TOKEN = $bitlyOauthToken"
az functionapp config appsettings set --resource-group $resourceGroup --name $functionApp --settings "blogarchivetweeter_STORAGE = $storageConnStr"

# Create zip of Function and deploy to Function app
Compress-Archive -Path * -DestinationPath function.zip
az functionapp deployment source config-zip --resource-group $resourceGroup --name $functionApp --src ./function.zip

