/**
 *-------------------------------------------------------------------------------
 * Name: Gnoppix Linux - Services
 * Architecture: all
 * Date: 2002-2026 by Gnoppix Linux
 * Author: Andreas Mueller
 * Website: https://www.gnoppix.com
 * Licence: Business Source License (BSL / BUSL)
 * You can use the code for free if your company or organisation doesn't have more than 2 people.
 *-------------------------------------------------------------------------------
 */

import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import LanguageDetector from 'i18next-browser-languagedetector'

const resources = {
  en: {
    translation: {
      ui: {
        sidebar: {
          settings: 'Settings',
          newMessage: 'New Message',
          addContact: 'Add Contact',
          initialize: 'Initialize Identity',
          register: 'Register',
          registerAll: 'Register All',
          checkRegister: 'Check Register',
          loadContacts: 'Load Contacts',
          connection: 'Connection',
          p2pListener: 'P2P Listener',
          running: 'Running',
          stopped: 'Stopped',
          startListener: 'Start Listener',
          stopListener: 'Stop Listener',
          restart: 'Restart',
          identity: 'Identity',
          close: 'Close',
        },
        chat: {
          online: 'Online',
          offline: 'Offline',
          typeMessage: 'Type a message...',
          sendMessage: 'Send',
          ttl: 'TTL',
          emoji: 'Emoji',
          noConversation: 'Select a conversation',
        },
        ttl: {
          title: 'Auto-destruct timer',
          off: 'No auto-destruct',
          hours2: '2 hours',
          hours12: '12 hours',
          hours24: '24 hours',
          hours48: '48 hours',
          days5: '5 days',
          days7: '7 days',
          days14: '14 days',
        },
        emoji: {
          title: 'Pick an emoji',
          categories: {
            smileys: '😊 Smileys',
            gestures: '👋 Gestures',
            objects: '💼 Objects',
            symbols: '❤️ Symbols',
            flags: '🚩 Flags',
          },
        },
        errors: {
          ipcNotAvailable: 'IPC API not available - is the CLI configured? Set ADD_CLI_PATH',
          initFailed: 'Init failed: {{error}}',
          startListenFailed: 'Start listen failed: {{error}}',
          stopListenFailed: 'Stop listen failed: {{error}}',
          restartListenFailed: 'Restart listen failed: {{error}}',
        },
        reflectorBot: {
          title: 'Reflector Bot',
          description: 'A default contact for testing latency and protocol verification. Sends E2E receipts. Echoes any message back.',
        },
      },
    },
  },
  de: {
    translation: {
      ui: {
        sidebar: {
          settings: 'Einstellungen',
          newMessage: 'Neue Nachricht',
          addContact: 'Kontakt hinzufügen',
          initialize: 'Identität initialisieren',
          register: 'Registrieren',
          registerAll: 'Alle registrieren',
          checkRegister: 'Registrierung prüfen',
          loadContacts: 'Kontakte laden',
          connection: 'Verbindung',
          p2pListener: 'P2P Listener',
          running: 'Läuft',
          stopped: 'Gestoppt',
          startListener: 'Starten',
          stopListener: 'Stoppen',
          restart: 'Neustarten',
          identity: 'Identität',
          close: 'Schließen',
        },
        chat: {
          online: 'Online',
          offline: 'Offline',
          typeMessage: 'Nachricht schreiben...',
          sendMessage: 'Senden',
          ttl: 'TTL',
          emoji: 'Emoji',
          noConversation: 'Konversation auswählen',
        },
        ttl: {
          title: 'Selbstzerstörungstimer',
          off: 'Kein automatischer Zerfall',
          hours2: '2 Stunden',
          hours12: '12 Stunden',
          hours24: '24 Stunden',
          hours48: '48 Stunden',
          days5: '5 Tage',
          days7: '7 Tage',
          days14: '14 Tage',
        },
        emoji: {
          title: 'Emoji auswählen',
          categories: {
            smileys: '😊 Smileys',
            gestures: '👋 Gesten',
            objects: '💼 Objekte',
            symbols: '❤️ Symbole',
            flags: '🚩 Flaggen',
          },
        },
        errors: {
          ipcNotAvailable: 'IPC API nicht verfügbar - ist die CLI konfiguriert? Setzen Sie ADD_CLI_PATH',
          initFailed: 'Initialisierung fehlgeschlagen: {{error}}',
          startListenFailed: 'Listener starten fehlgeschlagen: {{error}}',
          stopListenFailed: 'Listener stoppen fehlgeschlagen: {{error}}',
          restartListenFailed: 'Listener neustarten fehlgeschlagen: {{error}}',
        },
        reflectorBot: {
          title: 'Reflexions-Bot',
          description: 'Ein Standard-Kontakt zum Testen der Latenz und Protokollüberprüfung. Sendet E2E-Bestätigungen. Echo einer beliebigen Nachricht.',
        },
      },
    },
  },
  es: {
    translation: {
      ui: {
        sidebar: {
          settings: 'Configuración',
          newMessage: 'Nuevo mensaje',
          addContact: 'Agregar contacto',
          initialize: 'Inicializar identidad',
          register: 'Registrar',
          registerAll: 'Registrar todo',
          checkRegister: 'Verificar registro',
          loadContacts: 'Cargar contactos',
          connection: 'Conexión',
          p2pListener: 'Escucha P2P',
          running: 'Activo',
          stopped: 'Detenido',
          startListener: 'Iniciar escucha',
          stopListener: 'Detener escucha',
          restart: 'Reiniciar',
          identity: 'Identidad',
          close: 'Cerrar',
        },
        chat: {
          online: 'En línea',
          offline: 'Desconectado',
          typeMessage: 'Escribe un mensaje...',
          sendMessage: 'Enviar',
          ttl: 'TTL',
          emoji: 'Emoji',
          noConversation: 'Selecciona una conversación',
        },
        ttl: {
          title: 'Temporizador de autodestrucción',
          off: 'Sin autodestrucción automática',
          hours2: '2 horas',
          hours12: '12 horas',
          hours24: '24 horas',
          hours48: '48 horas',
          days5: '5 días',
          days7: '7 días',
          days14: '14 días',
        },
        emoji: {
          title: 'Seleccionar emoji',
          categories: {
            smileys: '😊 Sonrisas',
            gestures: '👋 Gestos',
            objects: '💼 Objetos',
            symbols: '❤️ Símbolos',
            flags: '🚩 Banderas',
          },
        },
        errors: {
          ipcNotAvailable: 'API IPC no disponible - ¿está configurada la CLI? Establezca ADD_CLI_PATH',
          initFailed: 'Falló la inicialización: {{error}}',
          startListenFailed: 'Falló al iniciar escucha: {{error}}',
          stopListenFailed: 'Falló al detener escucha: {{error}}',
          restartListenFailed: 'Falló al reiniciar escucha: {{error}}',
        },
        reflectorBot: {
          title: 'Bot Reflejo',
          description: 'Contacto predeterminado para probar latencia y verificación de protocolo. Envía recibos E2E. Devuelve cualquier mensaje.',
        },
      },
    },
  },
  ja: {
    translation: {
      ui: {
        sidebar: {
          settings: '設定',
          newMessage: '新規メッセージ',
          addContact: '連絡先を追加',
          initialize: 'IDを初期化',
          register: '登録',
          registerAll: '全て登録',
          checkRegister: '登録確認',
          loadContacts: '連絡先を読み込み',
          connection: '接続',
          p2pListener: 'P2Pリスナー',
          running: '実行中',
          stopped: '停止中',
          startListener: '開始',
          stopListener: '停止',
          restart: '再起動',
          identity: 'ID',
          close: '閉じる',
        },
        chat: {
          online: 'オンライン',
          offline: 'オフライン',
          typeMessage: 'メッセージを入力...',
          sendMessage: '送信',
          ttl: 'TTL',
          emoji: '絵文字',
          noConversation: '会話を選択してください',
        },
        ttl: {
          title: '自動削除タイマー',
          off: '自動削除なし',
          hours2: '2時間',
          hours12: '12時間',
          hours24: '24時間',
          hours48: '48時間',
          days5: '5日',
          days7: '7日',
          days14: '14日',
        },
        emoji: {
          title: '絵文字を選択',
          categories: {
            smileys: '😊 スマイリー',
            gestures: '👋 手の形',
            objects: '💼 オブジェクト',
            symbols: '❤️ シンボル',
            flags: '🚩 旗',
          },
        },
        errors: {
          ipcNotAvailable: 'IPC APIが利用できません - CLIは設定されていますか？ ADD_CLI_PATHを設定してください',
          initFailed: '初期化に失敗しました: {{error}}',
          startListenFailed: 'リスナーの開始に失敗しました: {{error}}',
          stopListenFailed: 'リスナーの停止に失敗しました: {{error}}',
          restartListenFailed: 'リスナーの再起動に失敗しました: {{error}}',
        },
        reflectorBot: {
          title: '反射ボット',
          description: 'レイテンシーとプロトコル検証をテストするためのデフォルト連絡先。E2Eレシートを送信します。任意のメッセージをエコーします。',
        },
      },
    },
  },
  fr: {
    translation: {
      ui: {
        sidebar: {
          settings: 'Paramètres',
          newMessage: 'Nouveau message',
          addContact: 'Ajouter un contact',
          initialize: 'Initialiser l\'identité',
          register: 'S\'inscrire',
          registerAll: 'Tout s\'inscrire',
          checkRegister: 'Vérifier l\'inscription',
          loadContacts: 'Charger les contacts',
          connection: 'Connexion',
          p2pListener: 'Écouteur P2P',
          running: 'En cours',
          stopped: 'Arrêté',
          startListener: 'Démarrer',
          stopListener: 'Arrêter',
          restart: 'Redémarrer',
          identity: 'Identité',
          close: 'Fermer',
        },
        chat: {
          online: 'En ligne',
          offline: 'Hors ligne',
          typeMessage: 'Écrire un message...',
          sendMessage: 'Envoyer',
          ttl: 'TTL',
          emoji: 'Émoji',
          noConversation: 'Sélectionner une conversation',
        },
        ttl: {
          title: 'Minuterie d\'autodestruction',
          off: 'Pas d\'autodestruction',
          hours2: '2 heures',
          hours12: '12 heures',
          hours24: '24 heures',
          hours48: '48 heures',
          days5: '5 jours',
          days7: '7 jours',
          days14: '14 jours',
        },
        emoji: {
          title: 'Choisir un émoji',
          categories: {
            smileys: '😊 Smileys',
            gestures: '👋 Gestures',
            objects: '💼 Objets',
            symbols: '❤️ Symboles',
            flags: '🚩 Drapeaux',
          },
        },
        errors: {
          ipcNotAvailable: 'API IPC non disponible - CLI configuré ? Définir ADD_CLI_PATH',
          initFailed: 'Échec de l\'initialisation : {{error}}',
          startListenFailed: 'Échec du démarrage de l\'écoute : {{error}}',
          stopListenFailed: 'Échec de l\'arrêt de l\'écoute : {{error}}',
          restartListenFailed: 'Échec du redémarrage de l\'écoute : {{error}}',
        },
        reflectorBot: {
          title: 'Bot Réflecteur',
          description: 'Contact par défaut pour tester la latence et vérifier le protocole. Envoie des reçus E2E. Renvoie tout message.',
        },
      },
    },
  },
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false,
    },
    detection: {
      order: ['localStorage', 'navigator'],
      caches: ['localStorage'],
    },
  })

export default i18n