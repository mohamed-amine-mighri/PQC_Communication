# Signature-ESP32  
## Évaluation comparative des signatures post-quantiques sur ESP32

---

## Présentation

Ce dépôt contient la composante **ESP32-WROOM-32** d’une étude expérimentale portant sur l’évaluation comparative de mécanismes de signature post-quantique (PQC) standardisés par le NIST.

L’objectif est d’analyser, sur plateforme embarquée :

- Les performances computationnelles
- L’empreinte mémoire
- La consommation énergétique
- Le coût global d’un protocole de signature

L’implémentation inclut :

- Benchmark local instrumenté
- Instrumentation temporelle haute précision
- Mesure mémoire détaillée (heap + stack)
- Marqueurs batch compatibles Nordic Power Profiler Kit II (PPK2)
- Support des signatures PQC (PQClean)
- Référence RSA-2048 (mbedTLS)
- Mode interopérable ESP32 ↔ Raspberry Pi

Ce projet s’inscrit dans un stage de maîtrise en **Intelligence Artificielle et Sciences des Données – Université de Sherbrooke**.

---

# Objectifs scientifiques

1. Mesurer le temps d’exécution de :

- `keypair`
- `sign`
- `verify`
- `whole`

2. Mesurer l’empreinte mémoire :

- Heap libre global
- Heap minimum pendant l’opération
- Réduction du plus grand bloc libre
- Utilisation de la stack

3. Mesurer la consommation énergétique via :

- Nordic Power Profiler Kit II (PPK2)
- Fenêtres de mesure synchronisées

4. Garantir la reproductibilité expérimentale

---

# Algorithmes supportés

Implémentations issues de **PQClean** :

- ML-DSA-44  
- ML-DSA-65  
- ML-DSA-87  

- Falcon-512  
- Falcon-1024  

- SPHINCS+ SHA2  
- SPHINCS+ SHAKE  

Référence classique :

- RSA-2048 (mbedTLS)

---

# Structure du dépôt

signature-esp32/
│
├── main/
│ ├── app_main.c
│ ├── bench_local.c
│ ├── bench_common.c
│ ├── dsa.c
│ ├── randombytes_esp32.c
│
├── components/
│ └── DSA/
│ ├── falcon-*
│ ├── ml-dsa-*
│ ├── sphincs-*
│ └── mayo/
│
├── CMakeLists.txt
├── sdkconfig
│
├── build/
└── results/



---

# Environnement de développement

ESP-IDF requis.

Installation :

```bash
git clone https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh
source export.sh

Compilation
idf.py build

Flash sur la carte :

idf.py -p /dev/ttyUSB0 flash monitor


Paramètres de benchmark

Les paramètres sont passés à la compilation :

Paramètre	Description
BENCH_ALG	algorithme testé
BENCH_OP	opération
KEYPAIR_ITERS	nombre d’itérations keypair
SV_ITERS	nombre d’itérations sign/verify
WHOLE_ITERS	nombre d’itérations whole
WARMUP	nombre d’itérations warmup
MSG_LEN	taille du message
Exemple d’exécution
Keypair
idf.py -p /dev/ttyUSB0 \
-D BENCH_ALG=ML_DSA_44 \
-D BENCH_OP=keypair \
-D KEYPAIR_ITERS=30 \
-D SV_ITERS=0 \
-D WHOLE_ITERS=0 \
build flash monitor
Signature
idf.py -p /dev/ttyUSB0 \
-D BENCH_ALG=ML_DSA_44 \
-D BENCH_OP=sign \
-D KEYPAIR_ITERS=0 \
-D SV_ITERS=30 \
build flash monitor
Vérification
idf.py -p /dev/ttyUSB0 \
-D BENCH_ALG=ML_DSA_44 \
-D BENCH_OP=verify \
-D KEYPAIR_ITERS=0 \
-D SV_ITERS=30 \
build flash monitor
Whole
idf.py -p /dev/ttyUSB0 \
-D BENCH_ALG=ML_DSA_44 \
-D BENCH_OP=whole \
-D WHOLE_ITERS=30 \
build flash monitor
Format des résultats

Les résultats sont imprimés au format JSONL :

{
 "platform_id":"esp32-local",
 "mode":"local",
 "pqc_sig_alg":"ML_DSA_44",
 "bench_op":"sign",
 "iter_idx":0,
 "msg_len_bytes":32,
 "time_us":52154,
 "heap_before":239416,
 "heap_after":239416,
 "heap_delta_bytes":0,
 "heap_min_free_global_bytes":239148,
 "heap_min_during_bytes":239416,
 "largest_before_bytes":126976,
 "largest_min_during_bytes":126976,
 "static_stack_used_bytes":39204,
 "total_mem_bytes":39204,
 "pk_len_bytes":1312,
 "sk_len_bytes":2560,
 "sig_len_bytes":2420,
 "ok":1
}

Chaque ligne correspond à une itération indépendante.

Métriques mémoire

Les métriques collectées permettent une analyse fine :

métrique	description
heap_before	heap libre avant opération
heap_after	heap libre après opération
heap_min_during	minimum observé pendant l’opération
largest_before	plus grand bloc libre
largest_min_during	plus grand bloc libre pendant exécution
static_stack_used_bytes	stack utilisée
total_mem_bytes	estimation mémoire totale

Ces métriques permettent d’estimer :

pic de mémoire

pression sur l’allocateur

fragmentation mémoire

Mesure énergétique (PPK2)

Les marqueurs suivants sont utilisés :

###MEAS_START###
...
###MEAS_STOP###

La consommation doit être intégrée sur la fenêtre complète.

Description des opérations
keypair

Mesure uniquement :

crypto_sign_keypair
sign

Keypair générée hors fenêtre

Mesure uniquement la signature

verify

Signature préparée hors fenêtre

Mesure uniquement la vérification

whole

Fenêtre complète :

keypair + sign + verify
Bonnes pratiques expérimentales

Warmup ≥ 5

Iters ≥ 30

Répéter les mesures ≥ 5 fois

Utiliser médiane ou moyenne

Fixer la fréquence CPU

Interopérabilité ESP32 ↔ Raspberry Pi

Le système permet :

Signature sur ESP32

Vérification sur Raspberry Pi

Communication via :

UART

Reproductibilité scientifique

Documenter :

Version ESP-IDF

Version compilateur

Fréquence CPU

Tension d’alimentation

Configuration PPK2

Paramètres CLI

Les résultats doivent être présentés avec :

Médiane

IQR

Écart-type

Contexte académique

Plateformes étudiées :

ESP32-WROOM-32

Raspberry Pi 4 Model B

Métriques analysées :

Latence

Empreinte mémoire

Consommation énergétique

Coût protocolaire global

Auteur

Mamadou Senghor
Maîtrise – Intelligence Artificielle et Sciences des Données
Université de Sherbrooke



