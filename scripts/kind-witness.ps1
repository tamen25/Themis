param(
 [ValidateSet('up','install','down')][string]$Action='up',
 [string]$ClusterName='',
 [string]$CommandProxy='rtk'
)
$ErrorActionPreference='Stop'
$repository=Split-Path -Parent $PSScriptRoot
if($Action -eq 'up' -and -not $ClusterName){$ClusterName='themis-t41-'+[guid]::NewGuid().ToString('N').Substring(0,12)}
if($ClusterName -notmatch '^themis-t41-[a-f0-9]{12}$'){throw 'Exact fresh T4.1 owned cluster name required'}
if($Action -eq 'up'){& (Join-Path $PSScriptRoot 'kind-experiment.ps1') -Action up -ClusterName $ClusterName -CommandProxy $CommandProxy}
if($Action -eq 'down'){& (Join-Path $PSScriptRoot 'kind-experiment.ps1') -Action down -ClusterName $ClusterName -CommandProxy $CommandProxy;return}
$runnerState=Join-Path $repository ('.themis/'+$ClusterName)
$witnessState=Join-Path $repository ('.themis/witness-'+$ClusterName)
$adminConfig=Join-Path $runnerState 'admin-kubeconfig';$context='kind-'+$ClusterName
$encoding=[Text.UTF8Encoding]::new($false)
function Tool([string]$Program,[string[]]$Arguments){$preference=$ErrorActionPreference;$ErrorActionPreference='Continue';try{$output=& $CommandProxy proxy $Program @Arguments;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$preference};if($code -ne 0){throw "$Program exited $code"};return $output}
function Kube([string[]]$Arguments){Tool 'kubectl' (@('--kubeconfig',$adminConfig,'--context',$context)+$Arguments)}
function Guard {
 $owner=Get-Content -LiteralPath (Join-Path $runnerState 'execution-owner.json') -Raw|ConvertFrom-Json
 $bootstrap=Get-Content -LiteralPath (Join-Path $runnerState 'bootstrap-owner.json') -Raw|ConvertFrom-Json
 if($owner.version -ne 'themis.kind-ownership/t4.1-v1' -or $owner.clusterName -ne $ClusterName -or $owner.context -ne $context -or $bootstrap.clusterName -ne $ClusterName -or $bootstrap.clusterUID -ne $owner.clusterUID -or $bootstrap.namespaceUID -ne $owner.namespaceUID){throw 'Immutable installer ownership missing; no adoption'}
 if((Kube @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}')) -ne $owner.clusterUID -or (Kube @('get','namespace','themis-test','-o','jsonpath={.metadata.uid}')) -ne $owner.namespaceUID){throw 'Cluster identity drift; mutation refused'}
 return $owner
}
function Protect([string]$Path,[bool]$Directory){
 if($env:OS -eq 'Windows_NT'){$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;if($Directory){$acl=[Security.AccessControl.DirectorySecurity]::new();$inherit='ContainerInherit,ObjectInherit'}else{$acl=[Security.AccessControl.FileSecurity]::new();$inherit='None'};$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,'None','Allow'));Set-Acl -LiteralPath $Path -AclObject $acl}else{$mode=if($Directory){'700'}else{'600'};Tool 'chmod' @($mode,$Path)|Out-Null}
}
function PrivateFile([string]$Name,[string]$Content){$path=Join-Path $witnessState $Name;if(Test-Path -LiteralPath $path){throw 'Witness files are exclusive'};[IO.File]::WriteAllText($path,$Content,$encoding);Protect $path $false;return $path}
Push-Location -LiteralPath $repository
try {
 $owner=Guard
 if(Test-Path -LiteralPath $witnessState){throw 'Dedicated witness state must be new'}
 New-Item -ItemType Directory -Path $witnessState|Out-Null;Protect $witnessState $true
 $pods=(Kube @('get','pods','-n','themis-test','-l','app=themis-latency-fixture','-o','json'))-join "`n"|ConvertFrom-Json
 if($pods.items.Count -ne 1){throw 'One owned fixture required'}
 $pod=$pods.items[0];$rs=@($pod.metadata.ownerReferences|Where-Object controller)[0].name
 $manifest=[IO.File]::ReadAllText((Join-Path $repository 'config/kubernetes/witness-rbac.yaml')).Replace('REPLACE_WITH_POD_NAME',$pod.metadata.name).Replace('REPLACE_WITH_REPLICA_SET_NAME',$rs)
 $path=PrivateFile 'witness-rbac.yaml' $manifest
 $null=Guard;Kube @('create','-f',$path)
 $uid=Kube @('get','serviceaccount','themis-witness','-n','themis-test','-o','jsonpath={.metadata.uid}')
 $null=Guard;$token=Kube @('create','token','themis-witness','-n','themis-test','--duration=1h')
 $admin=(Kube @('config','view','--raw','--minify','-o','json'))-join "`n"|ConvertFrom-Json;$cluster=$admin.clusters[0].cluster
 $config=[ordered]@{apiVersion='v1';kind='Config';clusters=@(@{name=$context;cluster=@{server=$cluster.server;'certificate-authority-data'=$cluster.'certificate-authority-data'}});contexts=@(@{name=$context;context=@{cluster=$context;user='themis-witness';namespace='themis-test'}});'current-context'=$context;users=@(@{name='themis-witness';user=@{token=$token}})}
 $null=PrivateFile 'witness-kubeconfig' ($config|ConvertTo-Json -Depth 8)
 $identity=[ordered]@{version='themis.kind-witness-owner/v1alpha1';clusterName=$ClusterName;context=$context;clusterUID=$owner.clusterUID;namespaceUID=$owner.namespaceUID;actor=@{name='system:serviceaccount:themis-test:themis-witness';uid=$uid};deploymentUID=$owner.deploymentUID}
 $null=PrivateFile 'witness-owner.json' ($identity|ConvertTo-Json -Depth 5)
 Write-Output "Installed observation-only Kubernetes principal for $ClusterName. Controller and runner RBAC unchanged."
}finally{Pop-Location}
