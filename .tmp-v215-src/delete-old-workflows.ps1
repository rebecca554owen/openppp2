# 删除除最近一次外的所有 workflow runs
# 使用方法：在 PowerShell 中运行此脚本，输入你的 GitHub Token

$owner = "Miaocchi"
$repo = "openppp2"
$token = Read-Host "请输入 GitHub Personal Access Token (需要 repo 或 workflow 权限)"

$headers = @{
    Authorization = "Bearer $token"
    Accept = "application/vnd.github.v3+json"
}

# 获取所有 workflow runs
Write-Host "正在获取 workflow runs..."
$url = "https://api.github.com/repos/$owner/$repo/actions/runs?per_page=100"
$response = Invoke-RestMethod -Uri $url -Headers $headers

if ($response.total_count -eq 0) {
    Write-Host "没有找到 workflow runs"
    exit
}

$runs = $response.workflow_runs
Write-Host "找到 $($runs.Count) 个 workflow runs"

# 保留最新的一个，删除其他的
$runsToDelete = $runs | Select-Object -Skip 1

if ($runsToDelete.Count -eq 0) {
    Write-Host "只有一个 workflow run，无需删除"
    exit
}

Write-Host "准备删除 $($runsToDelete.Count) 个旧的 workflow runs..."
foreach ($run in $runsToDelete) {
    $deleteUrl = "https://api.github.com/repos/$owner/$repo/actions/runs/$($run.id)"
    try {
        Invoke-RestMethod -Uri $deleteUrl -Headers $headers -Method Delete
        Write-Host "已删除 run #$($run.id) - $($run.name) - $($run.created_at)"
    } catch {
        Write-Host "删除 run #$($run.id) 失败: $_"
    }
}

Write-Host "完成！保留了最新的 workflow run"
