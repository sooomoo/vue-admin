<script setup lang="ts">
import log from 'loglevel'
import { onUnmounted, onMounted, ref } from 'vue'
import {
  onWebSocketMessage,
  postConnectCmdToWebSocket,
  closeWebSocket,
  startWebSocket,
} from './workers/websocket'
import { hideSplashScreen } from './core/splash_screen'
import { decodeSecrets, getClientId } from './core/net/http'

const token = ref('')

onMounted(async () => {
  log.debug('App mounted', performance.now())
  startWebSocket()
  onWebSocketMessage((event) => {
    log.debug('Received message from shared worker:', event.data)
  })
  postConnectCmdToWebSocket('ws://localhost:8080')

  const stoken = localStorage.getItem('token')
  log.debug('session token', stoken)

  window.addEventListener('storage', (event) => {
    log.debug('变化的键: ', event.key);
    log.debug('旧值: ', event.oldValue);
    log.debug('新值: ', event.newValue);
    log.debug('变化发生的 URL: ', event.url);
  })

  // hide splash screen after app mounted
  hideSplashScreen()
  const clientId = getClientId()
  log.debug('clientId', clientId)

  const [keyPair, signKeyPair] = decodeSecrets()
  log.debug('keyPair', keyPair)
  log.debug('signKeyPair', signKeyPair)
})

onUnmounted(() => {
  log.debug(performance.now())
  log.debug('Unmounted')
  closeWebSocket()
})

const handleClick = () => {
  log.debug('token', token.value)
  localStorage.setItem('token', token.value)
}
</script>

<template>
  <img alt="Vue logo" class="logo" src="@/assets/logo.svg" width="125" height="125" />
  <div class="wrapper">
    <input type="text" v-model="token" />
    <button @click="handleClick">click me</button>
  </div>
</template>

<style scoped>
header {
  line-height: 1.5;
  max-height: 100vh;
}

.logo {
  display: block;
  margin: 0 auto 2rem;
}

nav {
  width: 100%;
  font-size: 12px;
  text-align: center;
  margin-top: 2rem;
}

nav a.router-link-exact-active {
  color: var(--color-text);
}

nav a.router-link-exact-active:hover {
  background-color: transparent;
}

nav a {
  display: inline-block;
  padding: 0 1rem;
  border-left: 1px solid var(--color-border);
}

nav a:first-of-type {
  border: 0;
}

@media (min-width: 1024px) {
  header {
    display: flex;
    place-items: center;
    padding-right: calc(var(--section-gap) / 2);
  }

  .logo {
    margin: 0 2rem 0 0;
  }

  header .wrapper {
    display: flex;
    place-items: flex-start;
    flex-wrap: wrap;
  }

  nav {
    text-align: left;
    margin-left: -1rem;
    font-size: 1rem;

    padding: 1rem 0;
    margin-top: 1rem;
  }
}
</style>
