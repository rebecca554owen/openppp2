import { writable } from 'svelte/store'

export const instances = writable([])
export const selectedInstance = writable('')
export const isConnected = writable(false)
