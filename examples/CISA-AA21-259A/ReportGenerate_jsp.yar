rule ReportGenerate_jsp {
   strings:
      $s1 = "decrypt(fpath)"
      $s2 = "decrypt(fcontext)"
      $s3 = "decrypt(commandEnc)"
      $s4 = "upload failed!"
      $s5 = "sevck"
      $s6 = "newid"
   condition:
      filesize < 15KB and 4 of them
}