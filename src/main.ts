import './assets/main.css'

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import log from 'loglevel'

import App from './App.vue'
import router from './router'

log.setLevel(import.meta.env.PROD ? 'error' : 'debug')

const app = createApp(App)

app.use(createPinia())
app.use(router)

app.mount('#app')
