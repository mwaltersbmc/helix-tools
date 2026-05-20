/* Generated from use-cases.json - run update-bundled-data.ps1 after editing the JSON. */
window.HITT_USE_CASES = {
  "meta": {
    "tool": "Helix IS Triage Tool (HITT)",
    "scriptUrl": "https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh",
    "docsRepoPath": "hitt/",
    "groupingHelp": "Edit topics[] for section titles and order. Each use case has topicId (must match a topic id) and order (sort key within that section, lower first)."
  },
  "topics": [
    {
      "id": "getting-started",
      "title": "Getting Started and Configuring HITT",
      "order": 10
    },
    {
      "id": "jenkins-checks",
      "title": "Jenkins Checks & Configuration",
      "order": 20
    },
    {
      "id": "helix-deployment",
      "title": "Helix Deployment Checks and Options",
      "order": 30
    },
    {
      "id": "pipeline-mgmt",
      "title": "Jenkins Pipeline Management",
      "order": 40
    },
    {
      "id": "helix-is-mgmt",
      "title": "Helix IS Management Options",
      "order": 50
    },
    {
      "id": "tctl-options",
      "title": "tctl Options",
      "order": 60
    },
    {
      "id": "other-features",
      "title": "Other Features",
      "order": 70
    },
    {
      "id": "hitt-results",
      "title": "HITT Results",
      "order": 80
    },
    {
      "id": "hitt-help",
      "title": "HITT Help and Troubleshooting",
      "order": 90
    }
  ],
  "useCases": [
    {
      "id": "download-hitt",
      "topicId": "getting-started",
      "order": 10,
      "title": "I want to download the HITT script",
      "commands": [
        "mkdir hitt && cd hitt && curl -sO https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh",
        "chmod a+x hitt.sh   # optional"
      ],
      "notes": [
        "Optional: curl -O https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/dbjars.tgz in the same directory to enable database validation (see README).",
        "Run as the git user on the Deployment Engine where Jenkins is installed."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#quick-start"
    },
    {
      "id": "hitt-config-change",
      "topicId": "getting-started",
      "order": 20,
      "title": "I want to change my HITT configuration",
      "commands": [
        "vi hitt.conf",
        "rm hitt.conf && bash hitt.sh -m post-hp"
      ],
      "notes": [
        "Or delete the file and re-run HITT to be prompted again — use the second command above. The cluster must be reachable for namespace discovery when recreating hitt.conf interactively.",
        "hitt.conf holds HP_NAMESPACE, IS_NAMESPACE, IS_CUSTOMER_SERVICE, IS_ENVIRONMENT, Jenkins host/credentials, and tool paths.",
        "For a second config file without renaming the default, keep multiple files and pass -c /path/to/other.conf when you run HITT."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#configuration"
    },
    {
      "id": "alt-config",
      "topicId": "getting-started",
      "order": 30,
      "title": "I want to use a different hitt.conf file",
      "commands": [
        "bash hitt.sh -c /path/to/other.conf -m pre-is"
      ],
      "notes": [
        "Combine -c with any mode or feature that normally reads hitt.conf."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#configuration"
    },
    {
      "id": "update-hitt-latest",
      "topicId": "getting-started",
      "order": 40,
      "title": "I want to update to the latest version of the HITT script",
      "commands": [
        "cd /path/to/hitt && curl -sO https://raw.githubusercontent.com/mwaltersbmc/helix-tools/main/hitt/hitt.sh",
        "chmod a+x hitt.sh   # optional"
      ],
      "notes": [
        "Use the same directory where you keep hitt.sh and hitt.conf so settings are preserved.",
        "If you track the repo with git instead, pull the latest hitt/hitt.sh from helix-tools."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#quick-start"
    },
    {
      "id": "ignore-proxy",
      "topicId": "getting-started",
      "order": 50,
      "title": "I want to stop HITT from using my proxy",
      "commands": [
        "bash hitt.sh -x -m post-is"
      ],
      "notes": [
        "-x makes HITT ignore https_proxy / http_proxy / no_proxy for curl, openssl, and SSLPoke (see README Advanced CLI Options).",
        "Combine -x with whichever mode you need (example uses post-is)."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#advanced-cli-options"
    },
    {
      "id": "jenkins-check",
      "topicId": "jenkins-checks",
      "order": 10,
      "title": "I want to check the Jenkins configuration",
      "commands": [
        "bash hitt.sh -m jenkins"
      ],
      "notes": [
        "Validates nodes, credentials, libraries, and related Jenkins setup (read-only checks).",
        "Requires hitt.conf with working Jenkins host and credentials."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#running-hitt"
    },
    {
      "id": "dump-jenkins-creds",
      "topicId": "jenkins-checks",
      "order": 20,
      "title": "I want to display Jenkins credentials and pipeline passwords",
      "commands": [
        "bash hitt.sh -j",
        "bash hitt.sh -p -m pre-is"
      ],
      "notes": [
        "-j prints Jenkins credential usernames/passwords and can write kubeconfig.jenkins from the Jenkins kubeconfig credential.",
        "-p (with pre-is) writes pipeline parameter passwords into values.log during pre-is checks—use only on a trusted host and protect the output."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#advanced-cli-options"
    },
    {
      "id": "fix-kubeconfig",
      "topicId": "jenkins-checks",
      "order": 30,
      "title": "I want to update the Jenkins kubeconfig credential with a new kubeconfig file",
      "commands": [
        "bash hitt.sh -f \"jenkins kubeconfig\"",
        "bash hitt.sh -f \"jenkins kubeconfig /path/to/kubeconfig\""
      ],
      "notes": [
        "Without a path, HITT uses ~/.kube/config. The file is validated before updating the Jenkins credential.",
        "When Jenkins runs in-cluster, only certain jenkins fix sub-modes are allowed; see script messages if you hit that guard."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "fix-jenkins-credentials",
      "topicId": "jenkins-checks",
      "order": 40,
      "title": "I want to create/reset the Jenkins username/password credentials",
      "commands": [
        "bash hitt.sh -f \"jenkins credentials\""
      ],
      "notes": [
        "You will be prompted for the git user password where required.",
        "Does not update the kubeconfig credential; use jenkins kubeconfig separately."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "fix-jenkins-scriptapproval",
      "topicId": "jenkins-checks",
      "order": 50,
      "title": "I want to complete the Jenkins script approvals",
      "commands": [
        "bash hitt.sh -f \"jenkins scriptapproval\""
      ],
      "notes": [
        "Adds the approvals required for the deployment pipeline scripts (see README-fix-mode)."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "fix-jenkins-pipelinelibs",
      "topicId": "jenkins-checks",
      "order": 60,
      "title": "I want to reset/fix the Jenkins global shared library definitions",
      "commands": [
        "bash hitt.sh -f \"jenkins pipelinelibs\"",
        "bash hitt.sh -f \"jenkins pipelinelibs /path/to/LIBRARY_REPO\""
      ],
      "notes": [
        "Creates or updates the pipeline-framework and JENKINS-27413-workaround-library global trusted libraries.",
        "Without a path, you are prompted to pick the library .git directory."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "fix-jenkins-dryrun",
      "topicId": "jenkins-checks",
      "order": 70,
      "title": "I want to start a dry run of all the Helix pipelines",
      "commands": [
        "bash hitt.sh -f \"jenkins dryrun\""
      ],
      "notes": [
        "Dry-run builds all Helix deployment pipelines—useful after swapping git repo content for an upgrade (see README-fix-mode)."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "fix-jenkins-all",
      "topicId": "jenkins-checks",
      "order": 80,
      "title": "I want to run all Jenkins-oriented fixes at once (new Jenkins host)",
      "commands": [
        "bash hitt.sh -f \"jenkins all\""
      ],
      "notes": [
        "Runs the Jenkins fix bundle except dryrun. Review README-fix-mode for what each piece does."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "fix-realm",
      "topicId": "helix-deployment",
      "order": 10,
      "title": "I want to create the SSO realm for my Helix IS deployment",
      "commands": [
        "bash hitt.sh -f realm"
      ],
      "notes": [
        "Creates or updates the Helix Service Management SSO realm from hitt.conf (IS namespace, CUSTOMER_SERVICE, ENVIRONMENT).",
        "Can be used after Helix Platform is installed to add the realm before IS deployment."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "fix-resetssopwd",
      "topicId": "helix-deployment",
      "order": 20,
      "title": "I want to reset the SSO admin password to the default value",
      "commands": [
        "bash hitt.sh -f resetssopwd"
      ],
      "notes": [
        "Confirms the SSO Admin user exists, then prompts before resetting to the BMC default password."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "mode-post-hp",
      "topicId": "helix-deployment",
      "order": 30,
      "title": "I want to run checks on the Helix Platform deployment (post-hp)",
      "commands": [
        "bash hitt.sh -m post-hp"
      ],
      "notes": [
        "Validates Helix Platform and RSSO realm configuration; skips Jenkins checks.",
        "Requires hitt.conf with HP namespace and related settings."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#features--modes"
    },
    {
      "id": "mode-pre-is",
      "topicId": "helix-deployment",
      "order": 40,
      "title": "I want to check HELIX_ONPREM_DEPLOYMENT pipeline values before a deployment (pre-is)",
      "commands": [
        "bash hitt.sh -m pre-is"
      ],
      "notes": [
        "Run after HELIX_GENERATE_CONFIG completes; validates pipeline inputs against the cluster and Jenkins.",
        "To export or inspect raw parameter JSON from Jenkins builds, use pipeline mode (-k \"get …\") in Jenkins Pipeline Management."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#features--modes"
    },
    {
      "id": "mode-post-is",
      "topicId": "helix-deployment",
      "order": 50,
      "title": "I want to run checks on the Helix IS deployment (post-is)",
      "commands": [
        "bash hitt.sh -m post-is"
      ],
      "notes": [
        "Post-deployment Helix IS checks; requires hitt.conf and cluster access.",
        "Some checks deploy a short-lived tctl job/pod like HELIX_ITSM_INTEROPS, then remove it."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#features--modes"
    },
    {
      "id": "troubleshoot-failed-onprem-pipeline",
      "topicId": "helix-deployment",
      "order": 55,
      "title": "I want to troubleshoot a failed HELIX_ONPREM_DEPLOYMENT pipeline build",
      "commands": [
        "bash hitt.sh -m pre-is",
        "bash hitt.sh -m post-is"
      ],
      "notes": [
        "Start with pre-is: it validates HELIX_ONPREM_DEPLOYMENT inputs against Jenkins and the cluster (same timing as before a fresh deploy—useful even after a failure to catch bad parameters or drift).",
        "If the pipeline run is in service or upgrade mode (changing an already deployed environment), run post-is next. post-is exercises checks against the live Helix IS deployment and can surface issues in the current stack that relate to the failure."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#features--modes"
    },
    {
      "id": "pipeline-get",
      "topicId": "pipeline-mgmt",
      "order": 10,
      "title": "I want to view or save pipeline values to a file",
      "commands": [
        "bash hitt.sh -k \"get defaults\"",
        "bash hitt.sh -k \"get last\"",
        "bash hitt.sh -k \"get lastsuccessful\"",
        "bash hitt.sh -k \"get 42\"",
        "bash hitt.sh -k \"get lastsuccessful values.json\""
      ],
      "notes": [
        "Outputs JSON to the console unless you pass a filename as the last argument.",
        "Requires Jenkins in hitt.conf and working credentials."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#pipeline-mode"
    },
    {
      "id": "pipeline-build",
      "topicId": "pipeline-mgmt",
      "order": 20,
      "title": "I want to push saved pipeline values into Jenkins as a new build",
      "commands": [
        "bash hitt.sh -k \"build values.json\""
      ],
      "notes": [
        "After this, open HELIX_ONPREM_DEPLOYMENT in Jenkins, rebuild the last job, and review parameters (README warns the generated build is expected to fail until you adjust values).",
        "PRODUCT sub-pipelines are forced off so a full deploy does not start from this step alone."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#pipeline-mode"
    },
    {
      "id": "pipeline-console",
      "topicId": "pipeline-mgmt",
      "order": 30,
      "title": "I want the Jenkins console log for a pipeline",
      "commands": [
        "bash hitt.sh -o helix_onprem_deployment"
      ],
      "notes": [
        "PIPELINE_NAME is the Jenkins job name as shown in the URL (underscores)."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#display-jenkins-pipeline-console-output"
    },
    {
      "id": "utility-dbid",
      "topicId": "helix-is-mgmt",
      "order": 10,
      "title": "I want the current IS database ID (DBID) from the cluster",
      "commands": [
        "bash hitt.sh -u \"get dbid\""
      ],
      "notes": [
        "Uses hitt.conf, cluster access, and IS REST to read the current DBID (licensing)."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-utility-mode.md"
    },
    {
      "id": "utility-jwt",
      "topicId": "helix-is-mgmt",
      "order": 20,
      "title": "I want an AR-JWT token for the IS REST API",
      "commands": [
        "bash hitt.sh -u \"get jwt\"",
        "bash hitt.sh -u \"get jwt myuser\""
      ],
      "notes": [
        "Default user is hannah_admin with password resolved from the cluster when no user is given.",
        "With a username only, password is prompted if not passed as a second argument."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-utility-mode.md"
    },
    {
      "id": "fix-cacerts",
      "topicId": "helix-is-mgmt",
      "order": 30,
      "title": "I want to replace the Helix IS cacerts secret with a new keystore file",
      "commands": [
        "bash hitt.sh -f \"cacerts /path/to/newcacertsfile\""
      ],
      "notes": [
        "You are prompted to confirm when the new file validates."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "fix-arlicense",
      "topicId": "helix-is-mgmt",
      "order": 40,
      "title": "I want to apply an AR / Innovation Suite license to the current system",
      "commands": [
        "bash hitt.sh -f \"arlicense BRD-123456\"",
        "bash hitt.sh -f \"arlicense LTD-761066 28-Apr-27\""
      ],
      "notes": [
        "Optional expiry uses DD-Mon-YY format when required for temporary keys."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "utility-gendbid",
      "topicId": "helix-is-mgmt",
      "order": 50,
      "title": "I want to generate a DBID string before deployment (from DB type and names)",
      "commands": [
        "bash hitt.sh -u \"gendbid mssql my-db-server.example.com arsystem\""
      ],
      "notes": [
        "DB_TYPE is one of: mssql, oracle, postgres.",
        "This does not call the cluster; it only computes the ID from the three values."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-utility-mode.md"
    },
    {
      "id": "fix-sat",
      "topicId": "helix-is-mgmt",
      "order": 60,
      "title": "I want to create the role and role binding for the IS Support Assistant Tool",
      "commands": [
        "bash hitt.sh -f sat"
      ],
      "notes": [
        "Creates assisttool-rl and assisttool-rlb in the Helix IS namespace when SAT was deployed without SUPPORT_ASSISTANT_CREATE_ROLE."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "tctl",
      "topicId": "tctl-options",
      "order": 10,
      "title": "I want to run a simple tctl command without installing tctl locally",
      "commands": [
        "bash hitt.sh -t \"get tenant\"",
        "bash hitt.sh -t \"get tenant 1912102789 -o json\""
      ],
      "notes": [
        "Deploys the same style job/pod used by HELIX_ITSM_INTEROPS; output prints when the job completes.",
        "Not valid for Helix Platform CORE-only deployments (script will error with the documented message).",
        "For a static tctl client config file, use bash hitt.sh -t config instead."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#tctl-mode"
    },
    {
      "id": "tctl-config",
      "topicId": "tctl-options",
      "order": 20,
      "title": "I want a tctl client config file",
      "commands": [
        "bash hitt.sh -t config",
        "bash hitt.sh -t config > config"
      ],
      "notes": [
        "Reads secrets and deployment data from the Helix Platform namespace and creates a tctl config file.",
        "SSO login credentials are written to the terminal for use when authenticating tctl.",
        "Requires hitt.conf and a full Helix Platform deployment."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#tctl-mode"
    },
    {
      "id": "utility-secret",
      "topicId": "other-features",
      "order": 10,
      "title": "I want to show the contents of a Kubernetes secret",
      "commands": [
        "bash hitt.sh -u \"get secret SECRET_NAME NAMESPACE\""
      ],
      "notes": [
        "First argument is the secret name, second is the namespace (matches kubectl -n).",
        "Printable keys are shown as text; other keys are decoded to files in the current directory (see decodeK8sSecret in hitt.sh)."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-utility-mode.md"
    },
    {
      "id": "bundle-status",
      "topicId": "other-features",
      "order": 20,
      "title": "I want an IS bundle deployment status from a bundle ID",
      "commands": [
        "bash hitt.sh -b PACKAGE_ID_FROM_PIPELINE"
      ],
      "notes": [
        "ID is the value from the pipeline STATUS URI (see README example)."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#get-is-bundle-deployment-status"
    },
    {
      "id": "results-suggested-fixes",
      "topicId": "hitt-results",
      "order": 10,
      "title": "I want to see suggested fixes for HITT errors",
      "commands": [
        "bash hitt.sh -m post-is",
        "less hittmsgs.log"
      ],
      "notes": [
        "After any mode run, open hittmsgs.log for cause, impact, and suggested fix text for each ERROR/WARNING (see README Log Files).",
        "The console summary points at message IDs; pair with “long help for a specific message ID” when you need the full text in the terminal."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#log-files"
    },
    {
      "id": "error-message-help",
      "topicId": "hitt-results",
      "order": 20,
      "title": "I want to see the long help text for a specific HITT message ID",
      "commands": [
        "bash hitt.sh -e 127"
      ],
      "notes": [
        "Use the numeric ID shown in parentheses after ERROR or WARNING, e.g. (127).",
        "The command must be exactly two script arguments after the shell name (e.g. hitt.sh -e 127) so the built-in lookup runs and then exits."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#advanced-cli-options"
    },
    {
      "id": "results-support-bundle",
      "topicId": "hitt-results",
      "order": 30,
      "title": "I want to send HITT output to BMC Helix Support",
      "commands": [
        "bash hitt.sh -m post-is",
        "ls -la hittlogs.zip"
      ],
      "notes": [
        "Run the modes you need first; HITT collects logs into hittlogs.zip (see README).",
        "Attach hittlogs.zip to your support case when BMC asks for diagnostic output."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#log-files"
    },
    {
      "id": "results-log-files",
      "topicId": "hitt-results",
      "order": 40,
      "title": "I want to know what log files HITT creates",
      "commands": [
        "ls -la hitt*.log values.log *.log hittlogs.zip 2>/dev/null"
      ],
      "notes": [
        "Common outputs: hitt.log (script output), hittmsgs.log (cause, impact, suggested fix per message), values.log (pre-is when using -p), hittdebug.log, PIPELINE_NAME.log console captures, and hittlogs.zip (bundle for support)."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#log-files"
    },
    {
      "id": "verbose-logging",
      "topicId": "hitt-help",
      "order": 10,
      "title": "I want HITT logging to be more verbose",
      "commands": [
        "bash hitt.sh -v -m post-is"
      ],
      "notes": [
        "-v increases verbosity of logging (see README Advanced CLI Options).",
        "Combine with the mode you are troubleshooting."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#advanced-cli-options"
    },
    {
      "id": "utility-help",
      "topicId": "hitt-help",
      "order": 20,
      "title": "I want a list of utility mode commands",
      "commands": [
        "bash hitt.sh -u help"
      ],
      "notes": [
        "Same summary content as README-utility-mode.md."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-utility-mode.md"
    },
    {
      "id": "fix-help",
      "topicId": "hitt-help",
      "order": 30,
      "title": "I want a list of fix mode commands",
      "commands": [
        "bash hitt.sh -f help"
      ],
      "notes": [
        "Prints the same categories as README-fix-mode.md tables."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README-fix-mode.md"
    },
    {
      "id": "debug-trace",
      "topicId": "hitt-help",
      "order": 40,
      "title": "I want HITT debug output",
      "commands": [
        "bash hitt.sh -d -m post-is"
      ],
      "notes": [
        "With default logging (no -l), HITT enables set -x before running main and still tees output to hitt.log.",
        "If you pass -l to disable log files, the script currently runs main without the tee branch, so -d does not enable set -x in that combination—omit -l when you need xtrace."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#advanced-cli-options"
    },
    {
      "id": "debug-stop-on-error",
      "topicId": "hitt-help",
      "order": 50,
      "title": "I want debug output and stop on error # for troubleshooting",
      "commands": [
        "bash hitt.sh -d -e 0 -m post-is",
        "bash hitt.sh -d -e 127 -m post-is"
      ],
      "notes": [
        "-e 0 exits the first time stopOnError runs (any logged ERROR or WARNING that invokes it), useful with -d to freeze right after the first failure.",
        "Use a specific ID (e.g. 127) to stop only when that message is raised."
      ],
      "seeAlso": "https://github.com/mwaltersbmc/helix-tools/blob/main/hitt/README.md#advanced-cli-options"
    }
  ]
};
