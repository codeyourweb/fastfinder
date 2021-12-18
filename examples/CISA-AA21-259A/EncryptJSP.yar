rule EncryptJSP {
   strings:
      $s1 = "AEScrypt"
      $s2 = "AES/CBC/PKCS5Padding"
      $s3 = "SecretKeySpec"
      $s4 = "FileOutputStream"
      $s5 = "getParameter"
      $s6 = "new ProcessBuilder"
      $s7 = "new BufferedReader"
      $s8 = "readLine()"
   condition:
      filesize < 15KB and 6 of them
}