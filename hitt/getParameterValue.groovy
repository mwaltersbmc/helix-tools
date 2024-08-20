import jenkins.model.*
import hudson.model.*

def jobName = 'HELIX_ONPREM_DEPLOYMENT'
def paramName = 'PARAMETER_NAME'

// Get the Jenkins instance
def jenkins = Jenkins.instance

// Get the job
def job = jenkins.getItemByFullName(jobName)
if (job == null) {
    println "Job not found: ${jobName}"
    return
}

// Get the last build
def lastBuild = job.getLastBuild()
if (lastBuild == null) {
    println "No builds found for job: ${jobName}"
    return
}

// Get the parameters from the last build
def parametersAction = lastBuild.getAction(ParametersAction)
if (parametersAction == null) {
    println "No parameters found for the last build of job: ${jobName}"
    return
}

// Find the parameter value
def parameterValue = parametersAction.getParameter(paramName)?.value
if (parameterValue == null) {
    println "Parameter '${paramName}' not found in the last build of job: ${jobName}"
} else {
    println "Parameter '${paramName}' value: ${parameterValue}"
}
