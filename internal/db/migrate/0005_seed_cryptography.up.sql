-- Seed cryptography catalogue (idempotent)
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('TDEA','Block cipher','["ECB", "CBC", "CFB", "OFB", "CTR"]'::jsonb,'["KAT", "MMT", "MCT"]'::jsonb,'[112, 168]'::jsonb,64,64,'ISO/IEC 18033-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('MISTY1','Block cipher','["ECB", "CBC", "CFB", "OFB"]'::jsonb,'["KAT", "MMT"]'::jsonb,'[128]'::jsonb,64,64,'ISO/IEC 18033-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('CAST-128','Block cipher','["ECB", "CBC", "CFB", "OFB", "CTR"]'::jsonb,'["KAT", "MMT"]'::jsonb,'[40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128]'::jsonb,64,64,'ISO/IEC 18033-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('HIGHT','Block cipher','["ECB", "CBC", "CFB", "OFB", "CTR"]'::jsonb,'["KAT", "MMT"]'::jsonb,'[128]'::jsonb,64,64,'ISO/IEC 18033-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('AES','Block cipher','["ECB", "CBC", "CFB", "OFB", "CTR", "GCM"]'::jsonb,'["KAT", "MMT", "MCT"]'::jsonb,'[128, 192, 256]'::jsonb,128,128,'ISO/IEC 18033-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('Camellia','Block cipher','["ECB", "CBC", "CFB", "OFB", "CTR"]'::jsonb,'["KAT", "MMT", "MCT"]'::jsonb,'[128, 192, 256]'::jsonb,128,128,'ISO/IEC 18033-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SEED','Block cipher','["ECB", "CBC", "CFB", "OFB", "CTR"]'::jsonb,'["KAT", "MMT"]'::jsonb,'[128]'::jsonb,128,128,'ISO/IEC 18033-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('MUGI','Stream cipher','[]'::jsonb,'["KAT", "MMT"]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 18033-4','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SNOW2','Stream cipher','[]'::jsonb,'["KAT", "MMT"]'::jsonb,'[128]'::jsonb,NULL,NULL,'ISO/IEC 18033-4','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('Rabbit','Stream cipher','[]'::jsonb,'["KAT", "MMT"]'::jsonb,'[128]'::jsonb,NULL,NULL,'ISO/IEC 18033-4','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('Decimv2','Stream cipher','[]'::jsonb,'["KAT", "MMT"]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 18033-4','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('Kcipher-2','Stream cipher','[]'::jsonb,'["KAT", "MMT"]'::jsonb,'[128]'::jsonb,NULL,NULL,'ISO/IEC 18033-4','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('RIPEMD-160','Hash','[]'::jsonb,'[]'::jsonb,'[160]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('RIPEMD-128','Hash','[]'::jsonb,'[]'::jsonb,'[128]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA-1','Hash','[]'::jsonb,'[]'::jsonb,'[160]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA-256','Hash','[]'::jsonb,'[]'::jsonb,'[256]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA-384','Hash','[]'::jsonb,'[]'::jsonb,'[384]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA-512','Hash','[]'::jsonb,'[]'::jsonb,'[512]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('WHIRLPOOL','Hash','[]'::jsonb,'[]'::jsonb,'[512]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA-224','Hash','[]'::jsonb,'[]'::jsonb,'[224]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA-512/224','Hash','[]'::jsonb,'[]'::jsonb,'[224]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA-512/256','Hash','[]'::jsonb,'[]'::jsonb,'[256]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('STREEBOG-512','Hash','[]'::jsonb,'[]'::jsonb,'[512]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','GOST R 34.11-2012')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('STREEBOG-256','Hash','[]'::jsonb,'[]'::jsonb,'[256]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','GOST R 34.11-2012')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA3-224','Hash','[]'::jsonb,'[]'::jsonb,'[224]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA3-256','Hash','[]'::jsonb,'[]'::jsonb,'[256]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA3-384','Hash','[]'::jsonb,'[]'::jsonb,'[384]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SHA3-512','Hash','[]'::jsonb,'[]'::jsonb,'[512]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('SM3','Hash','[]'::jsonb,'[]'::jsonb,'[256]'::jsonb,NULL,NULL,'ISO/IEC 10118-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('MAC','MAC','["CBC-MAC", "CMAC"]'::jsonb,'["KAT", "MMT"]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 9797-2','Generic placeholder')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('DRBG','RNG','[]'::jsonb,'["KAT"]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 18031','Generic placeholder')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('DSA Integer Factorisation based Techniques','Asymmetric','[]'::jsonb,'["KAT"]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 9796-2','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('DSA Discrete Logarithm based Techniques','Asymmetric','[]'::jsonb,'["KAT"]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 9796-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('DSA with Appendix','Asymmetric','[]'::jsonb,'["KAT"]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 14888','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('RSA','Asymmetric','[]'::jsonb,'["KAT"]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 18033-2','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('ECDSA','Asymmetric','[]'::jsonb,'["KAT"]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 15946','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('Key Management using symmetric techniques','Key Management','[]'::jsonb,'[]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 11770-2','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('Key Management using asymmetric techniques','Key Management','[]'::jsonb,'[]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 11770-3','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('Key Management mechanisms based on weak secrets','Key Management','[]'::jsonb,'[]'::jsonb,'[]'::jsonb,NULL,NULL,'ISO/IEC 11770-4','')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;
INSERT INTO cryptography(algorithm, category, modes, test_modes, key_lengths, block_size_bits, iv_size_bits, standard_ref, notes)
VALUES ('Post Quantum Cryptography','PQC','[]'::jsonb,'[]'::jsonb,'[]'::jsonb,NULL,NULL,'','Umbrella entry')
ON CONFLICT (algorithm) DO UPDATE SET 
  category=EXCLUDED.category,
  modes=EXCLUDED.modes,
  test_modes=EXCLUDED.test_modes,
  key_lengths=EXCLUDED.key_lengths,
  block_size_bits=EXCLUDED.block_size_bits,
  iv_size_bits=EXCLUDED.iv_size_bits,
  standard_ref=EXCLUDED.standard_ref,
  notes=EXCLUDED.notes;