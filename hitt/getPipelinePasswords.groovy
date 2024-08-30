import jenkins.model.*
import hudson.model.*

def jobName = 'HELIX_ONPREM_DEPLOYMENT'

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

// Extract parameters from the last build
def parameters = lastBuild.getAction(ParametersAction.class)?.getParameters()
def paramMap = [:]

if (parameters != null) {
    parameters.each { param ->
        if (param.getName() ==~ ".*PASSWORD.*") {
          paramMap[param.getName()] = param.getValue()
        }
    }
}

// Output the parameters in JSON format
def jsonOutput = new groovy.json.JsonBuilder(paramMap).toPrettyString()
println(jsonOutput)
