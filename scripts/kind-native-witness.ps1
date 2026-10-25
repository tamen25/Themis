param(
 [ValidateSet('up','refresh','down')][string]$Action='up',
 [string]$ClusterName='',
 [string]$CommandProxy=''
)
$ErrorActionPreference='Stop'
$repository=Split-Path -Parent $PSScriptRoot
if($Action -eq 'up' -and -not $ClusterName){$ClusterName='themis-t42-'+[guid]::NewGuid().ToString('N').Substring(0,12)}
if($ClusterName -notmatch '^themis-t42-[a-f0-9]{12}$'){throw 'Fresh exact native installer-owned cluster required'}
# Reuse the reviewed ownership, target installation, bounded fixture and teardown.
& (Join-Path $PSScriptRoot 'kind-dependency.ps1') -Action $Action -ClusterName $ClusterName -CommandProxy $CommandProxy
if($Action -eq 'down'){return}
$state=Join-Path $repository ('.themis/'+$ClusterName)
$witness=Join-Path $state 'witness';$admin=Join-Path $state 'admin-kubeconfig';$context='kind-'+$ClusterName
$encoding=[Text.UTF8Encoding]::new($false)
function Tool([string]$Program,[string[]]$Arguments){$preference=$ErrorActionPreference;$ErrorActionPreference='Continue';try{if($CommandProxy){$output=& $CommandProxy proxy $Program @Arguments}else{$output=& $Program @Arguments};$code=$LASTEXITCODE}finally{$ErrorActionPreference=$preference};if($code -ne 0){throw "$Program exited $code"};return $output}
function Kube([string[]]$Arguments){Tool 'kubectl' (@('--kubeconfig',$admin,'--context',$context)+$Arguments)}
function Guard {
 $o=Get-Content -LiteralPath (Join-Path $state 'bootstrap.json') -Raw|ConvertFrom-Json
 if($o.clusterName -ne $ClusterName -or $o.namespace -ne ('themis-dep-'+$ClusterName.Substring(11)) -or -not $o.clusterUID -or -not $o.namespaceUID -or -not $o.engineID -or $env:DOCKER_CONTEXT -or $env:DOCKER_HOST -ne $o.endpoint -or $o.context -ne $context -or $o.nodeID -notmatch '^[a-f0-9]{64}$' -or (Tool 'docker' @('--host',$o.endpoint,'info','--format','{{.ID}}')) -ne $o.engineID -or (Tool 'docker' @('--host',$o.endpoint,'inspect','--type','container','--format','{{.Id}}',($ClusterName+'-control-plane'))) -ne $o.nodeID){throw 'Original owned engine/cluster/namespace required'}
 if((Kube @('get','namespace','kube-system','-o','jsonpath={.metadata.uid}')) -ne $o.clusterUID -or (Kube @('get','namespace',$o.namespace,'-o','jsonpath={.metadata.uid}')) -ne $o.namespaceUID){throw 'Original Kubernetes ownership changed'}
 return $o
}
function Protect([string]$Path,[bool]$Directory){
 if($env:OS -eq 'Windows_NT'){$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;if($Directory){$acl=[Security.AccessControl.DirectorySecurity]::new();$inherit='ContainerInherit,ObjectInherit'}else{$acl=[Security.AccessControl.FileSecurity]::new();$inherit='None'};$acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false);$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,'None','Allow'));Set-Acl -LiteralPath $Path -AclObject $acl}else{Tool 'chmod' @($(if($Directory){'700'}else{'600'}),$Path)|Out-Null}
}
function PrivateFile([string]$Name,[string]$Content,[bool]$Update=$false){$path=Join-Path $witness $Name;if((Test-Path -LiteralPath $path) -and -not $Update){throw 'Witness installation files are exclusive'};[IO.File]::WriteAllText($path,$Content,$encoding);if(-not $Update){Protect $path $false};return $path}
Push-Location -LiteralPath $repository
try {
 $owner=Guard;$new=$Action -eq 'up'
 if($new){if(Test-Path -LiteralPath $witness){throw 'No witness state adoption'};New-Item -ItemType Directory $witness|Out-Null;Protect $witness $true
  $manifest=[IO.File]::ReadAllText((Join-Path $repository 'config/kubernetes/native-witness-rbac.yaml')).Replace('REPLACE_NAMESPACE',$owner.namespace)
  $file=PrivateFile 'witness-rbac.yaml' $manifest;$null=Guard;Kube @('create','-f',$file)
 }
 $uid=Kube @('get','serviceaccount','native-witness','-n',$owner.namespace,'-o','jsonpath={.metadata.uid}')
 if($new){
  $null=Guard;$token=Kube @('create','token','native-witness','-n',$owner.namespace,'--duration=2h')
  $adminConfig=(Kube @('config','view','--raw','--minify','-o','json'))-join "`n"|ConvertFrom-Json;$cluster=$adminConfig.clusters[0].cluster
  $config=[ordered]@{apiVersion='v1';kind='Config';clusters=@(@{name=$context;cluster=@{server=$cluster.server;'certificate-authority-data'=$cluster.'certificate-authority-data'}});contexts=@(@{name=$context;context=@{cluster=$context;user='native-witness';namespace=$owner.namespace}});'current-context'=$context;users=@(@{name='native-witness';user=@{token=$token}})}
  $null=PrivateFile 'kubeconfig' ($config|ConvertTo-Json -Depth 8)
 }
 $identity=Get-Content -LiteralPath (Join-Path $state 'observer/owner.json') -Raw|ConvertFrom-Json
 $identity.role='witness';$identity.actor='system:serviceaccount:'+$owner.namespace+':native-witness';$identity.actorUID=$uid
 if(-not $new){$previous=Get-Content -LiteralPath (Join-Path $witness 'owner.json') -Raw|ConvertFrom-Json;if($previous.role -ne 'witness' -or $previous.actorUID -ne $uid -or $previous.clusterUID -ne $owner.clusterUID -or $previous.namespaceUID -ne $owner.namespaceUID){throw 'Original witness principal changed'}}
 $null=PrivateFile 'owner.json' ($identity|ConvertTo-Json -Depth 8) (-not $new)
 Write-Output "Installed native observation-only witness principal in $ClusterName. No fault was executed; existing Role rules remain unchanged."
}finally{Pop-Location}
