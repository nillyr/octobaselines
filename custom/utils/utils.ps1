# @copyright Copyright (c) 2021 Nicolas GRELLETY
# @license https://opensource.org/licenses/GPL-3.0 GNU GPLv3
# @link https://gitlab.internal.lan/octo-project/octobaselines
# @link https://github.com/nillyr/octobaselines
# @since 0.1.0

# Functions to ease the development of scripts

# Enable encryption
$global:ENABLE_ENCRYPTION = $False

# Create the RSA private key: openssl genpkey -out private.key -algorithm RSA -pkeyopt rsa_keygen_bits:4096
# Create a CSR: openssl req -new -key private.key -out certificate.csr
# Sign the CSR: openssl x509 -req -days 365 -in certificate.csr -signkey private.key -out certificate.crt
$Certificate="-----BEGIN CERTIFICATE-----
[...]
-----END CERTIFICATE-----"

Set-Variable -Name "AES_BLOCK_SIZE" -Value 128  -Option "ReadOnly"
Set-Variable -Name "AES_KEY_SIZE" -Value 256 -Option "ReadOnly"
Set-Variable -Name "RSA_KEY_SIZE" -Value 4096 -Option "ReadOnly"

$global:AesKey = $null


Function Encrypt-Asymmetric {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
        [String] $ClearText,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Cert
    )

    [System.Security.Cryptography.RSACryptoServiceProvider] $RSASP = $Cert.PublicKey.Key
    $RSACNG = [System.Security.Cryptography.RSACng]::new($RSA_KEY_SIZE)
    $RSACNG.ImportParameters($RSASP.ExportParameters($False));
    $RSASP.Dispose()

    $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($ClearText)
    try {
        $EncryptedByteArray = $RSACNG.Encrypt($ByteArray, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA384)
        $Base64String = [Convert]::ToBase64String($EncryptedByteArray)
    } catch {
        $RSACNG.Dispose()
        return $null
    }

    $RSACNG.Dispose()
    return $Base64String
}

Function Create-AesCngObject($Key, $IV) {
    $aesCng = New-Object System.Security.Cryptography.AesCng
    $aesCng.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesCng.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesCng.BlockSize = $AES_BLOCK_SIZE
    $aesCng.KeySize = $AES_KEY_SIZE

    If ($IV) {
        If ($IV.getType().Name -eq "String") {
            $aesCng.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesCng.IV = $IV
        }
    }
    If ($Key) {
        If ($Key.getType().Name -eq "String") {
            $aesCng.Key = [System.Convert]::FromBase64String($Key)
        }
        else {
            $aesCng.Key = $Key
        }
    }
    return $aesCng
}

Function Create-AesKey() {
    $aesCng = Create-AesCngObject
    $aesCng.GenerateKey()
    return [System.Convert]::ToBase64String($aesCng.Key)
}

Function Encrypt-Symetric() {
    Param(
        [Parameter(ValueFromPipeline=$true)] $UnencryptedString
    )

    Begin {}
    Process {
        If (!$global:ENABLE_ENCRYPTION) {
            return $UnencryptedString
        }

        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($UnencryptedString)
            # IV is auto generated from System.Security.Cryptography.AesCng
            $aesCng = Create-AesCngObject $global:AesKey

            $encryptor = $aesCng.CreateEncryptor()
            $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);

            [byte[]] $fullData = $aesCng.IV + $encryptedData
            $aesCng.Dispose()
        } catch {
            Write-Error "[x] Critical Error: Error while encrypting data.`nRun again the script with the option 'ENABLE_ENCRYPTION' disabled or check your settings.`n"
            Exit(1)
        }

        return [System.Convert]::ToBase64String($fullData)
    }
    End {}
}

Function Init-CryptoMaterial() {
    If ($Certificate -eq $null -or $Certificate -eq "") {
        return $null
    }

    $CertPath="$basedir\certificate.crt"
    Write-Output $Certificate | Out-File -Encoding utf8 -FilePath $CertPath
    try {
        $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
        $CertValidity = Test-Certificate -AllowUntrustedRoot -Cert $Cert
    } catch {
        return $null
    }

    If (!$CertValidity) {
        return $null
    }

    $global:AesKey = Create-AesKey

    $EncryptedKey = Encrypt-Asymmetric -ClearText $global:AesKey -Cert $Cert
    If (!$EncryptedKey) {
        return $null
    }

    $EncryptedKey | Out-File -Encoding utf8 -FilePath "$basedir\aes_key.enc"
    return 0
}

Function Test-CommandExists {
    Param ($command)

    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    try {
        If (Get-Command $command) {
            return $True
        }
    } catch {
        return $False
    } finally {
        $ErrorActionPreference = $oldPreference
    }
}

Function Get-SystemInfo() {
    $res = @"
$(whoami)@$([System.Net.Dns]::GetHostName())
--------------------------
Hostname: $([System.Net.Dns]::GetHostName())
OS: $((Get-CimInstance Win32_OperatingSystem).Caption) (Build $((Get-CimInstance Win32_OperatingSystem).Version))
"@
    $res += "`n`n"
    $res += & systeminfo.exe

    return $res
}

# This should never happen, but we never know.
# reason: this file is integrated in the generated script, which must initialize the variable.
If ($basedir -eq $null -or $basedir -eq "") {
    $basedir="$pwd\$($env:COMPUTERNAME)_$(Get-Date -f yyyyMMdd-hhmmss)"
    New-Item -ItemType Directory -Force -Path $basedir | Out-Null
}

If ($ENABLE_ENCRYPTION) {
    $status = Init-CryptoMaterial
    If ($status -eq $null) {
        Write-Error "[x] Critical Error: The specified settings do not allow the use of data encryption.`nRun again the script with the option 'ENABLE_ENCRYPTION' disabled or check your settings.`n"
        Exit(1)
    }
}

Get-SystemInfo | Encrypt-Symetric | Out-File -Encoding utf8 -FilePath $basedir\system_information.txt
