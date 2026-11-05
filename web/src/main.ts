import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/700.css';
import '@mineral-ui/design/styles.css';
import { applyTheme, applyTexture, currentTheme } from '@mineral-ui/design/themes';
import { mount } from 'svelte';
import App from './App.svelte';
import './app.css';

applyTexture('grid', false);
applyTheme(currentTheme(), false);
mount(App, { target: document.getElementById('app')! });
