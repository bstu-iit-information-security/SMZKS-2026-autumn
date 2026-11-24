$url = "http://127.0.0.1/api/login?username=admin&password=123"
$success = 0
$failed = 0
$codes = @{}

Write-Host "Запуск стресс-теста: 500 запросов..."
Write-Host "URL: $url"
Write-Host ""

for ($i = 1; $i -le 500; $i++) {
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5
        $code = $response.StatusCode
        if ($code -eq 200) {
            $success++
        } else {
            $failed++
        }
        if ($codes.ContainsKey($code)) {
            $codes[$code]++
        } else {
            $codes[$code] = 1
        }
    } catch {
        $failed++
        if ($codes.ContainsKey("Error")) {
            $codes["Error"]++
        } else {
            $codes["Error"] = 1
        }
    }
    
    if ($i % 100 -eq 0) {
        Write-Host "Прогресс: $i / 500"
    }
}

Write-Host ""
Write-Host "========== РЕЗУЛЬТАТЫ =========="
Write-Host "Всего запросов: 500"
Write-Host "Успешных (200 OK): $success"
Write-Host "Ошибок/Отклонённых: $failed"
Write-Host ""
Write-Host "Распределение кодов ответов:"
$codes.GetEnumerator() | ForEach-Object { Write-Host "  Код $($_.Key): $($_.Value) раз" }