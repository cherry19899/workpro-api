/**
 * Web Push text.
 *
 * Push payloads are rendered here, server-side, because the OS draws the
 * notification — unlike the in-app list, which renders from `notif_key` and so
 * always follows the reader's current UI language. Only the chat notifications
 * are ever pushed, so this table stays deliberately small; everything else is
 * translated on the client.
 *
 * The language comes from `users.lang`, last seen via the `x-lang` header on
 * GET /api/me. Unknown or missing language falls back to English.
 */
const PUSH = {
  msgFrom: {
    en: 'Message from {name}', ru: 'Сообщение от {name}', uk: 'Повідомлення від {name}',
    de: 'Nachricht von {name}', fr: 'Message de {name}', es: 'Mensaje de {name}',
    pt: 'Mensagem de {name}', it: 'Messaggio da {name}', tr: '{name} kişisinden mesaj',
    pl: 'Wiadomość od {name}', ar: 'رسالة من {name}', hi: '{name} का संदेश',
    zh: '来自 {name} 的消息', ja: '{name} からのメッセージ', ko: '{name}님의 메시지',
    vi: 'Tin nhắn từ {name}', id: 'Pesan dari {name}', th: 'ข้อความจาก {name}',
    tl: 'Mensahe mula kay {name}', nl: 'Bericht van {name}', sv: 'Meddelande från {name}',
    ro: 'Mesaj de la {name}', bn: '{name}-এর বার্তা',
  },
  fileFrom: {
    en: 'File from {name}', ru: 'Файл от {name}', uk: 'Файл від {name}',
    de: 'Datei von {name}', fr: 'Fichier de {name}', es: 'Archivo de {name}',
    pt: 'Arquivo de {name}', it: 'File da {name}', tr: '{name} kişisinden dosya',
    pl: 'Plik od {name}', ar: 'ملف من {name}', hi: '{name} से फ़ाइल',
    zh: '来自 {name} 的文件', ja: '{name} からのファイル', ko: '{name}님이 보낸 파일',
    vi: 'Tệp từ {name}', id: 'Berkas dari {name}', th: 'ไฟล์จาก {name}',
    tl: 'File mula kay {name}', nl: 'Bestand van {name}', sv: 'Fil från {name}',
    ro: 'Fișier de la {name}', bn: '{name}-এর ফাইল',
  },
};

function pushText(key, lang, params = {}) {
  const table = PUSH[key];
  if (!table) return '';
  const tpl = table[(lang || '').slice(0, 2)] || table.en;
  return tpl.replace(/\{(\w+)\}/g, (_m, k) => (params[k] == null ? '' : String(params[k])));
}

module.exports = { pushText };
