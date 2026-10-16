# Run from the repository root after the owned Kind setup. The output is JSON.
# Prepare first, inspect proposal.json, then separately execute approval with the
# exact reviewed digest. Do not derive approval automatically from untrusted CRs.
param(
    [ValidateSet('prepare','approve','start','status','cancel','reconcile','verify')][string]$Action='prepare',
    [Parameter(Mandatory=$true)][string]$Directory,
    [string]$ApprovedDigest=''
)
$runner=Join-Path (Get-Location) '.cache/themis-kube'
if($env:OS -eq 'Windows_NT'){$runner+='.exe'}
$arguments=@('coordinate',$Action,'--directory',$Directory)
if($Action -eq 'prepare'){$arguments+=@('--state','.themis/kind-t21','--run','latency-request')}
if($Action -eq 'approve'){
    if(-not $ApprovedDigest){throw 'Review proposal.json and provide -ApprovedDigest explicitly'}
    $arguments+=@('--approve-digest',$ApprovedDigest)
}
& $runner @arguments
exit $LASTEXITCODE
