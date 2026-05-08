# HITT Utility Mode #

**HITT's** utilty mode provides a colllection of tools that may be useful when working with Helix deployments.

## Modes ##

| Mode   | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `getdbid`   | Displays the database ID (DBID) for the system - used for licensing. |
| `getjwt`   | Prints an AR-JWT token for the IS REST API using `hannah_admin` credentials from the cluster. |
| `gendbid`   | Generates a database ID (DBID) using the values provided. |
| `decodesecret`  | Decodes Kubernetes secrets - see below. |

## Usage ##

Fix modes are called using the `-f <fixmode>` command line option.  Some of the fix commands require additional parameters in which case the mode and options must be enclosed in double quotes.

```bash
Examples:
bash hitt.sh -u getdbid # Get the current DBID
bash hitt.sh -u getjwt  # Get a JWT token for hannah_admin from the IS server
bash hitt.sh -u "decodesecret helix-is ar-global-secret" # Print the decoded contents of the ar-global-secret
```

#### `getdbid` - get the IS DBID from the system
```bash
bash hitt.sh -f getdbid
```
Displays the DB ID of the system that is required to generate a server license via the BMC web site.

#### `getjwt` - get an AR-JWT token for the IS REST API
```bash
bash hitt.sh -f getjwt
```
Authenticates to IS RESTAPI with the `hannah_admin` credentials and prints the string to set the ARJWT variable.

#### `gendbid` - generate an IS DBID from the provided values.
```bash
bash hitt.sh -f "gendbid DB_TYPE DATABASE_HOST_NAME AR_DB_NAME"
```
Generates the DB ID required to generate a server license via the BMC web site.  Useful to get a new license before making changes to the DB hostname.\
DB_TYPE is one of mssql|oracle|postgres\
DATABASE_HOST_NAME and AR_DB_NAME are the values you will use in the HELIX_ONPREM_DEPLOYMENT pipeline.

#### `"decodesecret NAMESPACE SECRETNAME"` - decode and display the contents of a Kubernetes secret
```bash
bash hitt.sh -u "decodesecret helix-is ar-global-secret"
```
Reads and displays data from a Kubernetes secret. Decodes base64 encoded values such as passwords.
