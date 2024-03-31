## Overview

`OneDriveTokenHandler` is a class that will manage and store tokens for Python scripts that need regular access to consumer OneDrives. It will cache refresh tokens in a Sqlite3 database and use them to retrieve subsequent access tokens, avoiding the need to re-authenticate with Microsoft each time.

It's main function, `get_token()`, will return a valid access token that can be used in Microsoft Graph API calls to consumer OneDrives.

In order for this to work your application must be [registered with Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app) and you must have a valid client id/app id.

## First time Usage

The first time you call `get_token()` a browser will open and present the Office 365 login screen. Users should logon as usual and accept the permissions of the application. Subsequent calls should not need to re-authenticate, they should use the refresh token stored in the database.

If the refresh token expires (currently 90-days without usage) or is deleted then authentication will be required again.

## Example Usage:

```python
import os
from OneDriveTokenHandler import OneDriveTokenHandler

token_handler = OneDriveTokenHandler(app_name='my-application', 
                                     client_id='12345678-abcd-1234-abcd-12345678', 
                                     scopes=['Files.ReadWrite.All', 'offline_access'], 
                                     db_filepath=os.path.expanduser('~/.local/share/my-application/settings_db')
new_token = token_handler.get_token()
```


## Parameters

| Parameter     | Req | Type     | Description                                                                                                                                                                                                                                                                                                                    |
|---------------|-----|----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `app_name`    | Y   | `string` | A name for your app. This is unique to `OneDriveTokenHandler` and really just used when the refresh-token is persisted so can be anything. It doesn't need to match the name of your app as it's registered in Azure, for instance.                                                                                      |
| `client_id`   | Y   | `string` | ClientId (also called AppId) of your app. This is generated once you've registered your App in Azure and can be retrieved by logging onto the Azure Portal and selecting *App Registrations*. Clicking on your registered app will show the *Application (client) Id* field in the *Essentials* section. Just copy this value. |
| `scopes`   | Y   | `[string]` | A list of [scopes](https://learn.microsoft.com/en-us/onedrive/developer/rest-api/concepts/permissions_reference?view=odsp-graph-online) that must be enabled for the access token (NOTE: if `offline_access` is not included in this list it's automatically added as it's required to retrieve a refresh token).                                                   |
| `db_filepath` | N   | `string` | (*optional*) Specifies the location/name of the Sqlite3 db database that stores the refresh token. Defaults to `./tokens.db`.                                                                                                                                                                                                   |                                                                                                                                                                   |

