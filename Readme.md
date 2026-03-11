# Signature-RaspberryPi  
## Évaluation comparative des signatures post-quantiques sur Raspberry Pi

---

## Présentation

Ce dépôt contient la composante **Raspberry Pi 4 Model B** d’une étude expérimentale portant sur l’évaluation comparative de mécanismes de signature post-quantique (PQC) standardisés par le NIST.

L’objectif est d’analyser, sur plateforme embarquée :

- Les performances computationnelles
- L’empreinte mémoire
- La consommation énergétique
- Le coût global d’un protocole de signature

L’implémentation inclut :

- Benchmark local instrumenté
- Mode idle-match pour isolation énergétique
- Mode interopérable ESP32 ↔ Raspberry Pi
- Instrumentation temporelle haute précision
- Mesure mémoire (heap + RSS)
- Marqueurs batch compatibles Nordic Power Profiler Kit II (PPK2)
- Référence RSA-2048 (OpenSSL)

Ce projet s’inscrit dans un stage de maîtrise en Intelligence Artificielle et Sciences des Données – Université de Sherbrooke.

---

# Objectifs scientifiques

1. Mesurer le temps d’exécution de :
   - `keypair`
   - `sign`
   - `verify`
   - `whole`

2. Mesurer l’empreinte mémoire :
   - Heap utilisé (`mallinfo2`)
   - RSS (`VmRSS`)

3. Mesurer la consommation énergétique par :
   - Fenêtre PPK2 par batch
   - Méthode RUN − IDLE-MATCH

4. Garantir la reproductibilité expérimentale

---

# Algorithmes supportés

Selon la version de `liboqs` installée :

- ML-DSA-44
- ML-DSA-65
- ML-DSA-87
- Falcon-512
- Falcon-1024
- SPHINCS+ (SHA2 / SHAKE variants)

Utiliser les noms `liboqs` exacts, par exemple :

--alg "ML-DSA-44"
--alg "Falcon-512"

# Structure du dépôt

Signature-RaspberryPi/
│
├── CMakeLists.txt
├── DSA-Test-local.c # Benchmark local (RUN + IDLE)
├── DSA-Test-interop.c # Mode ESP32 ↔ RPi
├── pingpong.c # Test UART
├── transport.*
├── queue.*
│
├── build/
└── results/


---

# Dépendances

## liboqs (obligatoire)

```bash
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DOQS_BUILD_ONLY_LIB=ON ..
make -j
sudo make install
sudo ldconfig

OpenSSL (optionnel – RSA référence)
sudo apt install libssl-dev


Compilation avec RSA :

cmake -DUSE_OPENSSL=ON ..

Compilation
rm -rf build
mkdir build && cd build
cmake -DUSE_OPENSSL=ON ..
cmake --build . -j


Exécutables générés :

build/dsa_local
build/pingpong

Utilisation – Benchmark local
Exemple PQC (mode RUN)
taskset -c 2 ./build/dsa_local \
  --op sign \
  --alg "ML-DSA-44" \
  --iters 5000 \
  --warmup 5 \
  --msg-len 32 \
  --mode run

Mode IDLE-MATCH
taskset -c 2 ./build/dsa_local \
  --op sign \
  --alg "ML-DSA-44" \
  --iters 5000 \
  --warmup 5 \
  --msg-len 32 \
  --mode idle

Paramètres CLI
--op keypair|sign|verify|all
--alg <algorithme|all>
--iters N
--warmup N
--msg-len N
--mode run|idle
--flush-each
--rsa

Format des résultats

Les résultats sont enregistrés au format JSONL :

results/local/{keypair,sign,verify,whole}/ALG.jsonl


Exemple :

{
 "platform":"rpi-local",
 "alg":"ML-DSA-44",
 "op":"sign",
 "iter":0,
 "msg_len":32,
 "time_us":23781,
 "heap_used_before":4688,
 "heap_used_after":8056,
 "rss_kb_before":1492,
 "rss_kb_after":1828,
 "pk_len":1312,
 "sk_len":2560,
 "sig_len":2420,
 "ok":1
}


Chaque ligne correspond à une itération indépendante.

Méthodologie de mesure énergétique
Fenêtre PPK2 (par batch)

Une seule fenêtre est émise par lot :

@@PPK2_BEGIN op=sign alg=ML-DSA-44 mode=run iters=5000 msg_len=32
@@PPK2_END   op=sign alg=ML-DSA-44 mode=run


L’intégration énergétique doit être réalisée sur cette fenêtre complète.

Isolation énergétique

Pour isoler le coût algorithmique :

Mesurer en mode run

Mesurer en mode idle

Calculer :

ΔI = I_run − I_idle


ou idéalement :

ΔQ = Q_run − Q_idle


où Q est la charge (Coulomb) mesurée par le PPK2.

Description des opérations
keypair

Fenêtre couvre uniquement la génération de clé.

sign

Keypair générée une seule fois (hors fenêtre)

Fenêtre couvre uniquement la boucle de signature

verify

Message signé préparé hors fenêtre

Fenêtre couvre uniquement la vérification

whole

Fenêtre couvre :

keypair + sign + verify

Bonnes pratiques expérimentales

Fixer l’exécution sur un cœur CPU :

taskset -c 2 ...


Governor CPU en mode performance si disponible

Warmup ≥ 5

Iters ≥ 30 (≥ 1000 recommandé pour énergie)

Répéter chaque mesure ≥ 5 fois

Utiliser médiane ou moyenne

Interopérabilité ESP32 ↔ Raspberry Pi

DSA-Test-interop.c permet :

Signature sur ESP32

Vérification sur Raspberry Pi

Communication via UART

pingpong.c valide la couche transport.

Reproductibilité scientifique

Documenter :

Version liboqs

Version OpenSSL

Version compilateur

Fréquence CPU

Tension d’alimentation

Configuration PPK2

Paramètres CLI utilisés

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