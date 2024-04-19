typeof browser<"u"&&(chrome=browser),(()=>{"use strict";var y={};const c=["ytd-watch-flexy:not([hidden]) ytd-enforcement-message-view-model > div.ytd-enforcement-message-view-model","yt-playability-error-supported-renderers#error-screen ytd-enforcement-message-view-model","tp-yt-paper-dialog .ytd-enforcement-message-view-model"];function m(r){let t=null;const e=new MutationObserver(()=>{t||(t=setTimeout(()=>{var o;if(((o=document.querySelector(c))==null?void 0:o.clientHeight)>0)try{r()}catch{}else t=null},1e3))});document.addEventListener("yt-navigate-start",()=>{clearTimeout(t),t=null}),document.addEventListener("DOMContentLoaded",()=>{e.observe(document.body,{childList:!0,subtree:!0,attributeFilter:["src","style"]})})}function u(r,t="440px"){if(document.querySelector("ghostery-iframe-wrapper"))return;const e=document.createElement("ghostery-iframe-wrapper"),o=e.attachShadow({mode:"closed"}),i=document.createElement("template");i.innerHTML=`
    <iframe src="${r}" frameborder="0"></iframe>
    <style>
      :host {
        all: initial;
        display: flex !important;
        align-items: flex-end;
        position: fixed;
        top: 10px;
        right: 10px;
        left: 10px;
        bottom: 10px;
        z-index: 2147483647;
        pointer-events: none;
      }

      iframe {
        display: block;
        flex-grow: 1;
        width: min(100%, ${t});
        pointer-events: auto;
        box-shadow: 30px 60px 160px rgba(0, 0, 0, 0.4);
        border-radius: 16px;
        background: linear-gradient(90deg, rgba(0, 0, 0, 0.13) 0%, rgba(0, 0, 0, 0.27) 100%);
        opacity: 0;
        transition: opacity 0.2s ease-in-out, transform 0.2s ease-in-out;
        transform: translateY(20px);
      }

      iframe.active {
        opacity: 1;
        transform: translateY(0);
      }

      @media screen and (min-width: 640px) {
        :host {
          justify-content: flex-end;
          align-items: start;
        }

        iframe {
          flex-grow: 0;
          transform: translateY(-20px);
          max-width: ${t};
        }
      }
    </style>
  `,o.appendChild(i.content),document.documentElement.appendChild(e);const n=o.querySelector("iframe");setTimeout(()=>{n.classList.add("active")},100),window.addEventListener("message",a=>{var d;switch((d=a.data)==null?void 0:d.type){case"ghostery-resize-iframe":{const{height:p,width:l}=a.data;n.style.height=p+"px",l&&(n.style.width=l+"px");break}case"ghostery-close-iframe":a.data.clear&&chrome.runtime.sendMessage({action:"clearIframe",url:r}),a.data.reload?window.location.reload():e.parentElement&&setTimeout(()=>e.parentElement.removeChild(e),0);break;case"ghostery-clear-iframe":n.src===a.data.url&&e.parentElement&&setTimeout(()=>e.parentElement.removeChild(e),0);break;default:break}})}function f(r=!1,t=!1){setTimeout(()=>{window.parent.postMessage({type:"ghostery-close-iframe",reload:r,clear:t},"*")},100)}function w(r){new ResizeObserver(()=>{window.parent.postMessage({type:"ghostery-resize-iframe",height:document.body.clientHeight,width:r},"*")}).observe(document.body,{box:"border-box"}),document.body.style.overflow="hidden",chrome.runtime.onMessage.addListener(e=>{e.action==="clearIframe"&&(console.log("clearIframe",e.url),window.parent.postMessage({type:"ghostery-clear-iframe",url:e.url},"*"))})}function s(){return new Promise(r=>{chrome.storage.local.get(["youtube_dont_show_again"],t=>{r(t.youtube_dont_show_again)})})}chrome.extension.inIncognitoContext||(async()=>await s()||(window.addEventListener("yt-navigate-start",()=>{f()},!0),m(async()=>{await s()||u(chrome.runtime.getURL(`app/templates/youtube.html?url=${encodeURIComponent(window.location.href)}`),"460px")})))()})();
