# Helix Authentication Troubleshooting Checklist

- [Pod Health](#pod-health)
- [RSSO Checks](#rsso-checks)
- [Jenkins HELIX_ONPREM_DEPLOYMENT Pipeline Checks](#jenkins-helixonpremdeployment-pipeline-checks)
- [Helix IS Platform Pod](#helix-is-platform-pod)
- [Certificate Issues](#certificate-issues)
	- [From Helix IS platform pod](#from-helix-is-platform-pod)
	- [From Deployment Engine](#from-deployment-engine)
- [Certificate Chain Tests](#certificate-chain-tests)
- [Add certificate(s) to the cacerts keystore file](#add-certificates-to-the-cacerts-keystore-file)
- [Recreate Helix IS cacerts Secret](#recreate-helix-is-cacerts-secret)

## Pod Health

Check that all pods are running and healthy using **kubectl get/describe pod**:

- Helix IS namespace — platform-fts/user/int/sr
- Helix Platform namespace — RSSO and Postgres

## RSSO Checks

Log in to RSSO as the admin user — default **admin/RSSO#Admin#**.

Click on the pin icon for the SAAS_TENANT and confirm that **Tenant: SAAS_TENANT** is displayed in the page header.

![RSSO tenant list](images/image-2024-3-5_12-38-16.png)

Note the name of the non-SAAS_TENANT — for example **red.60831950** in the example above.

Go to the **Realm** tab.

Confirm that a realm exists with the name format **CUSTOMER_SERVICE-ENVIRONMENT**, where these values come from the **HELIX_ONPREM_DEPLOYMENT** pipeline. In the example, CUSTOMER_SERVICE is **seal-red** and ENVIRONMENT is **itsm**, so the realm is called **seal-red-itsm**.

> **Note:** If the ENVIRONMENT value is **prod**, the realm name must still include it, even though the aliases in the realm will not.  For example, CUSTOMER_SERVICE=mydept-itsm and ENVIRONMENT=prod then the **realm name** must be mydept-itsm-prod.

Confirm that the **Tenant** for the realm is the same as the **Tenant Name** above.

![RSSO realm tenant](images/image-2024-3-5_12-49-42.png)

Edit the realm by clicking the pencil icon and verify that all expected hostnames are listed in **Application Domain(s)**.

Confirm there are no leading or trailing spaces around the **Tenant** value.

![RSSO realm application domains](images/image-2024-3-5_12-52-12.png)

Click the **Authentication** tab and verify that an entry exists for **AR** type authentication. Edit the entry.

The **Host** should be **platform-user-ext.HELIX-IS-NAMESPACE** and the port **46262**.

Validate using the **Test** button.

![RSSO AR authentication test](images/image-2024-3-5_12-55-41.png)

Test connectivity to RSSO from the Deployment Engine command line — replace **LB_HOST** with the customer value:

```bash
curl -sk -X POST https://LB_HOST/rsso/api/v1.1/admin/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"RSSO#Admin#"}'
```

Test that the **custom_cacert.pem** file contains valid certificate(s):

```bash
curl -s -X POST https://LB_HOST/rsso/api/v1.1/admin/login \
  --cacert /path/to/custom_cacert.pem \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"RSSO#Admin#"}'
```

## Jenkins HELIX_ONPREM_DEPLOYMENT Pipeline Checks

Check the **RSSO PARAMETERS** section of the pipeline run that was used to deploy IS.

- Make sure that the RSSO_URL ends in **/rsso** and is not just the LB_HOST URL.
- RSSO admin credentials are correct.
- The TENANT_DOMAIN should be the tenant name as shown in RSSO above.

![Jenkins RSSO parameters](images/image-2024-3-21_11-27-4.png)

## Helix IS Platform Pod

Use **kubectl exec** to get a command prompt in a Helix IS platform pod and check **/opt/bmc/ARSystem/db/arjavaplugin-authentication.log** and **/tmp/rsso.0.log** for errors.

Test connectivity to RSSO — this is expected to return an access token:

```bash
curl -sk -X POST $RSSO_SERVICE_URL/api/v1.1/admin/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"RSSO#Admin#"}'
```

![RSSO login from platform pod](images/image-2024-3-8_16-11-59.png)

Check the RSSO tenant/agent values:

```bash
cat /opt/bmc/ARSystem/conf/rsso.cfg
cat /opt/bmc/ARSystem/conf/rsso-agent.properties | grep sso-
```

![rsso.cfg example](images/image-2024-3-8_15-49-2.png)

![rsso-agent.properties example](images/image-2024-3-8_15-50-23.png)

## Certificate Issues

### From Helix IS platform pod

Check that the Java **cacerts** in the IS platform pod has the customer's certificate:
- pre-25.4.01 replace **XXX** with the alias name used when adding the certificate to the BMC-provided **cacerts** file.
- 25.4.01 onwards check for presence of one or more customcert* aliases

Substitute your keystore password in place of changeit if you set CACERTS_SSL_TRUSTSTORE_PASSWORD.

```bash
/opt/java/bin/keytool --list -cacerts -storepass changeit -alias XXX
/opt/java/bin/keytool --list -cacerts -storepass changeit | grep customcert
```

![keytool list alias](images/image-2024-3-8_15-45-48.png)

### From Deployment Engine

View certs from LB/ingress controller - substitute LB_HOST value:

```bash
openssl s_client -showcerts -connect LB_HOST:443
```

This example is a wildcard certificate for **\*.seal-k3s.bmc.com**, so it is valid for any host within that domain. See below for one using **Subject Alternate Names (SANs)**.

Look at the **issuer information** — the customer will need a valid certificate chain for this and any higher-level CAs.

![Wildcard certificate example](images/image-2024-3-8_15-53-5.png)

Certificate using **SANs**:

![SAN certificate example](images/image-2024-3-8_16-7-29.png)

Download and compile SSLPoke.java to test for a valid certificate in the **cacerts** file:

```bash
curl -s https://gist.githubusercontent.com/MatthewJDavis/50f3f92660af72c812e21b7ff6b56354/raw/7f258a30be4ddea7b67239b40ae305f6a2e98e0a/SSLPoke.java -o SSLPoke.java
javac SSLPoke.java
java -Djavax.net.ssl.trustStore=/path/to/cacerts SSLPoke LB_HOST 443
```

If the **cacerts** file does not include the required certificates you will see errors such as "unable to find valid certification path to requested target".

![SSLPoke certification path error](images/image-2024-3-8_16-4-21.png)

## Certificate Chain Tests

You can see if you have the full certificate chain and view certificate file details using [https://tools.keycdn.com/ssl](https://tools.keycdn.com/ssl).

Grab the data from the customer's PEM file, or use the **BEGIN .. / .. END** block from the **openssl** command above.

![KeyCDN SSL checker](images/image-2024-3-8_15-19-47.png)

This helps you see which CA issued the certificate and whether you need intermediate certificates.

## Add certificate(s) to the cacerts keystore file

If you need to update, or add a missing certificate, to the Java keystore used by the Helix IS platform pods:

- Get the current cacerts keystore from the Helix IS namespace:

```bash
kubectl get secret cacerts -o jsonpath='{.data.cacerts}' -n HELIX-IS-NAMESPACE | base64 -d > cacerts
```

- Import the new certificate(s), you will be prompted to accept the new certificate by the keytool command.  If you have more than one certificate to add, run this for each file (one certificate per file).

```bash
keytool -importcert -v -alias <alias name> -file <certificatefilename> -keystore cacerts -storepass <password>
```

Use the steps below to update the cacerts secret.

## Recreate Helix IS cacerts Secret

If you have a valid Java keystore **cacerts** file and want to update the one that is currently deployed:

- Back up the current cacerts secret and then delete it.

```bash
kubectl get secret cacerts -n HELIX-IS-NAMESPACE -o yaml > cacerts-secret-backup.yaml
kubectl delete secret cacerts -n HELIX-IS-NAMESPACE
```

- Create a new secret using the local cacerts file.  If the local file is named cacerts, use this command:

```bash
kubectl create secret generic cacerts --from-file=cacerts -n HELIX-IS-NAMESPACE
```

- If the local file is **not** named cacerts, use this command:

```bash
kubectl create secret generic cacerts --from-file=cacerts=LOCAL-FILENAME -n HELIX-IS-NAMESPACE
```

- Restart the platform pods.

```bash
kubectl -n HELIX-IS-NAMESPACE rollout restart statefulset/platform-fts
# Restart other platform workloads that mount cacerts if required, for example:
kubectl -n HELIX-IS-NAMESPACE rollout restart statefulset/platform-int
```
