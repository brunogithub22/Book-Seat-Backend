# Sistema di Autenticazione — Architettura con NGINX e Go

Documento di presentazione del progetto: un sistema di autenticazione che
supporta due modalità di accesso, login tramite Google e login tradizionale
basato su token, con un'architettura backend basata su **NGINX** e **Go**.

## Idea del progetto

L'obiettivo è costruire un sistema di autenticazione flessibile che permetta
a un utente di accedere in due modi diversi, mantenendo la stessa gestione
della sessione una volta effettuato l'accesso:

- **Login con Google**: l'utente si autentica con il proprio account Google,
  senza dover creare o ricordare una password dedicata al servizio.
- **Login senza Google (con token)**: l'utente si registra con email e
  password sul servizio stesso; dopo il login riceve un token che viene usato
  per autenticare le richieste successive.

## Architettura backend

- **Go**: è il linguaggio/framework usato per implementare il backend che
  gestisce entrambe le modalità di autenticazione — sia il flusso OAuth con
  Google sia la registrazione/login con email e password e generazione dei
  token.
- **NGINX**: si occupa di ricevere le richieste in ingresso e instradarle
  verso il servizio Go corretto, agendo da reverse proxy davanti al backend
  di autenticazione.

## Modalità 1 — Login con Google

- L'utente clicca su "Accedi con Google".
- Viene reindirizzato alla pagina di autenticazione di Google.
- Dopo l'autorizzazione, Google restituisce le informazioni base dell'account
  (email, nome, immagine profilo) al backend Go.
- Il backend Go crea (o riconosce, se già esistente) l'utente usando l'email
  come identificatore univoco.
- Viene creata una sessione per l'utente, senza che debba mai gestire una
  password sul servizio.

## Modalità 2 — Login senza Google (con token)

- L'utente si registra fornendo email e password.
- La password viene salvata in forma sicura (hash), mai in chiaro, gestita
  dal backend Go.
- Al login, se le credenziali sono corrette, il backend Go genera un
  **token** (es. JWT) che rappresenta la sessione dell'utente.
- Il token viene inviato al client e usato in ogni richiesta successiva per
  dimostrare che l'utente è autenticato, senza dover reinserire email e
  password ogni volta.
- Il token ha una scadenza, dopo la quale l'utente deve effettuare nuovamente
  il login.

## Punto in comune tra le due modalità

Indipendentemente dal metodo scelto (Google o token), il risultato finale è
lo stesso: l'utente ottiene una sessione autenticata riconosciuta dal
sistema. Questo permette di:

- Proteggere le pagine e le funzionalità riservate agli utenti loggati.
- Riconoscere sempre l'utente in modo univoco, sia che abbia usato Google sia
  che abbia usato email e password.
- Offrire una scelta all'utente su come preferisce accedere, senza duplicare
  la logica di gestione della sessione nel backend Go.

## Obiettivo finale

Dare all'utente la libertà di scegliere il metodo di accesso più comodo per
lui (Google o credenziali proprie), mantenendo un sistema di autenticazione
unico, sicuro e coerente, con NGINX come punto di ingresso e Go come motore
di tutta la logica di autenticazione.

## Integrazione con un progetto più grande

Questo sistema di autenticazione non è pensato come progetto isolato: è
parte di un progetto più ampio, attualmente in fase di lavorazione. L'idea è
che la gestione degli accessi (login con Google o con token), servita dietro
NGINX e implementata in Go, diventi il modulo di autenticazione condiviso da
usare all'interno del progetto principale, così da:

- Evitare di duplicare la logica di login/registrazione nel progetto più
  grande.
- Avere un unico punto di gestione degli utenti e delle sessioni, riutilizzato
  ovunque serva un accesso autenticato.
- Poter sviluppare e testare il sistema di autenticazione in autonomia, per
  poi collegarlo al progetto principale una volta stabile.