document.webL10n=function(w,l){function x(){var c=l.querySelector('script[type="application/l10n"]');return c?JSON.parse(c.innerHTML):null}function p(c){var b=l.createEvent("Event");b.initEvent("localized",!0,!1);b.language=c;l.dispatchEvent(b)}function o(c,b,e){var b=b||function(){},e=e||function(){console.warn(c+" not found.")},d=new XMLHttpRequest;d.open("GET",c,y);d.overrideMimeType&&d.overrideMimeType("text/plain; charset=utf-8");d.onreadystatechange=function(){4==d.readyState&&(200==d.status||
0===d.status?b(d.responseText):e())};d.onerror=e;d.ontimeout=e;try{d.send(null)}catch(a){e()}}function z(c,b,e,d){function a(a,c){function d(a,c,j){function r(){for(;;){if(!s.length){j();break}var a=s.shift();if(!h.test(a)){if(c){if(q=k.exec(a)){g=q[1].toLowerCase();o="*"!==g&&g!==b&&g!==p;continue}else if(o)continue;if(q=n.exec(a)){e(i+q[1],r);break}}(a=a.match(m))&&3==a.length&&(f[a[1]]=0>a[2].lastIndexOf("\\")?a[2]:a[2].replace(/\\\\/g,"\\").replace(/\\n/g,"\n").replace(/\\r/g,"\r").replace(/\\t/g,
"\t").replace(/\\b/g,"\u0008").replace(/\\f/g,"\u000c").replace(/\\{/g,"{").replace(/\\}/g,"}").replace(/\\"/g,'"').replace(/\\'/g,"'"))}}}var s=a.replace(l,"").split(/[\r\n]+/),g="*",p=b.split("-",1)[0],o=!1,q="";r()}function e(a,b){o(a,function(a){d(a,!1,b)},null)}var f={},l=/^\s*|\s*$/,h=/^\s*#|^\s*$/,k=/^\s*\[(.*)\]\s*$/,n=/^\s*@import\s+url\((.*)\)\s*$/i,m=/^([^=\s]*)\s*=\s*(.+)$/;d(a,!0,function(){c(f)})}var i=c.replace(/[^\/]*$/,"")||"./";o(c,function(b){g+=b;a(b,function(a){for(var b in a){var c,
d;d=b.lastIndexOf(".");0<d?(c=b.substring(0,d),d=b.substr(d+1)):(c=b,d=h);f[c]||(f[c]={});f[c][d]=a[b]}e&&e()})},d)}function A(c,b){function e(a){var b=a.href;this.load=function(a,c){z(b,a,c,function(){console.warn(b+" not found.");console.warn('"'+a+'" resource not found');k="";c()})}}c&&(c=c.toLowerCase());b=b||function(){};f={};k=g="";k=c;var d=l.querySelectorAll('link[type="application/l10n"]'),a=d.length;if(0===a){if((d=x())&&d.locales&&d.default_locale){console.log("using the embedded JSON directory, early way out");
f=d.locales[c];if(!f){var i=d.default_locale.toLowerCase(),j;for(j in d.locales)if(j=j.toLowerCase(),j===c){f=d.locales[c];break}else j===i&&(f=d.locales[i])}b()}else console.log("no resource to load, early way out");p(c);m="complete"}else{j=null;var h=0;j=function(){h++;h>=a&&(b(),p(c),m="complete")};for(i=0;i<a;i++)(new e(d[i])).load(c,j)}}function B(c){function b(a,b,c){return b<=a&&a<=c}var e={"0":function(){return"other"},1:function(a){return b(a%100,3,10)?"few":0===a?"zero":b(a%100,11,99)?"many":
2==a?"two":1==a?"one":"other"},2:function(a){return 0!==a&&0===a%10?"many":2==a?"two":1==a?"one":"other"},3:function(a){return 1==a?"one":"other"},4:function(a){return b(a,0,1)?"one":"other"},5:function(a){return b(a,0,2)&&2!=a?"one":"other"},6:function(a){return 0===a?"zero":1==a%10&&11!=a%100?"one":"other"},7:function(a){return 2==a?"two":1==a?"one":"other"},8:function(a){return b(a,3,6)?"few":b(a,7,10)?"many":2==a?"two":1==a?"one":"other"},9:function(a){return 0===a||1!=a&&b(a%100,1,19)?"few":
1==a?"one":"other"},10:function(a){return b(a%10,2,9)&&!b(a%100,11,19)?"few":1==a%10&&!b(a%100,11,19)?"one":"other"},11:function(a){return b(a%10,2,4)&&!b(a%100,12,14)?"few":0===a%10||b(a%10,5,9)||b(a%100,11,14)?"many":1==a%10&&11!=a%100?"one":"other"},12:function(a){return b(a,2,4)?"few":1==a?"one":"other"},13:function(a){return b(a%10,2,4)&&!b(a%100,12,14)?"few":1!=a&&b(a%10,0,1)||b(a%10,5,9)||b(a%100,12,14)?"many":1==a?"one":"other"},14:function(a){return b(a%100,3,4)?"few":2==a%100?"two":1==a%
100?"one":"other"},15:function(a){return 0===a||b(a%100,2,10)?"few":b(a%100,11,19)?"many":1==a?"one":"other"},16:function(a){return 1==a%10&&11!=a?"one":"other"},17:function(a){return 3==a?"few":0===a?"zero":6==a?"many":2==a?"two":1==a?"one":"other"},18:function(a){return 0===a?"zero":b(a,0,2)&&0!==a&&2!=a?"one":"other"},19:function(a){return b(a,2,10)?"few":b(a,0,1)?"one":"other"},20:function(a){return(b(a%10,3,4)||9==a%10)&&!b(a%100,10,19)&&!b(a%100,70,79)&&!b(a%100,90,99)?"few":0===a%1E6&&0!==
a?"many":2==a%10&&-1===[12,72,92].indexOf(a%100)?"two":1==a%10&&-1===[11,71,91].indexOf(a%100)?"one":"other"},21:function(a){return 0===a?"zero":1==a?"one":"other"},22:function(a){return b(a,0,1)||b(a,11,99)?"one":"other"},23:function(a){return b(a%10,1,2)||0===a%20?"one":"other"},24:function(a){return b(a,3,10)||b(a,13,19)?"few":-1!==[2,12].indexOf(a)?"two":-1!==[1,11].indexOf(a)?"one":"other"}},d={af:3,ak:4,am:4,ar:1,asa:3,az:0,be:11,bem:3,bez:3,bg:3,bh:4,bm:0,bn:3,bo:0,br:20,brx:3,bs:11,ca:3,cgg:3,
chr:3,cs:12,cy:17,da:3,de:3,dv:3,dz:0,ee:3,el:3,en:3,eo:3,es:3,et:3,eu:3,fa:0,ff:5,fi:3,fil:4,fo:3,fr:5,fur:3,fy:3,ga:8,gd:24,gl:3,gsw:3,gu:3,guw:4,gv:23,ha:3,haw:3,he:2,hi:4,hr:11,hu:0,id:0,ig:0,ii:0,is:3,it:3,iu:7,ja:0,jmc:3,jv:0,ka:0,kab:5,kaj:3,kcg:3,kde:0,kea:0,kk:3,kl:3,km:0,kn:0,ko:0,ksb:3,ksh:21,ku:3,kw:7,lag:18,lb:3,lg:3,ln:4,lo:0,lt:10,lv:6,mas:3,mg:4,mk:16,ml:3,mn:3,mo:9,mr:3,ms:0,mt:15,my:0,nah:3,naq:7,nb:3,nd:3,ne:3,nl:3,nn:3,no:3,nr:3,nso:4,ny:3,nyn:3,om:3,or:3,pa:3,pap:3,pl:13,ps:3,
pt:3,rm:3,ro:9,rof:3,ru:11,rwk:3,sah:0,saq:3,se:7,seh:3,ses:0,sg:0,sh:11,shi:19,sk:12,sl:14,sma:7,smi:7,smj:7,smn:7,sms:7,sn:3,so:3,sq:3,sr:11,ss:3,ssy:3,st:3,sv:3,sw:3,syr:3,ta:3,te:3,teo:3,th:0,ti:4,tig:3,tk:3,tl:4,tn:3,to:0,tr:0,ts:3,tzm:22,uk:11,ur:3,ve:3,vi:0,vun:3,wa:4,wae:3,wo:0,xh:3,xog:3,yo:0,zh:0,zu:3}[c.replace(/-.*$/,"")];return!(d in e)?(console.warn("plural form unknown for ["+c+"]"),function(){return"other"}):e[d]}function t(c,b,e){var d=f[c];if(!d){console.warn("#"+c+" is undefined.");
if(!e)return null;d=e}var e={},a;for(a in d){var i=d[a];var j=b,h=c,l=a,g=/\{\[\s*([a-zA-Z]+)\(([a-zA-Z]+)\)\s*\]\}/.exec(i);if(g&&g.length){var k=g[1],g=g[2],m=void 0;j&&g in j?m=j[g]:g in f&&(m=f[g]);k in n&&(i=(0,n[k])(i,m,h,l))}i=C(i,b,c);e[a]=i}return e}function C(c,b,e){return c.replace(/\{\{\s*(.+?)\s*\}\}/g,function(c,a){if(b&&a in b)return b[a];if(a in f)return f[a];console.log("argument {{"+a+"}} for #"+e+" is undefined.");return c})}function u(c){var b,e;if(c){b=c.getAttribute("data-l10n-id");
var d=c.getAttribute("data-l10n-args");e={};if(d)try{e=JSON.parse(d)}catch(a){console.warn("could not parse arguments for #"+b)}}else b=void 0,e=void 0;if(b)if(e=t(b,e)){if(e[h]){if(c.children)b=c.children.length;else if("undefined"!==typeof c.childElementCount)b=c.childElementCount;else for(d=b=0;d<c.childNodes.length;d++)b+=1===c.nodeType?1:0;if(0===b)c[h]=e[h];else{b=c.childNodes;for(var d=!1,f=0,g=b.length;f<g;f++)3===b[f].nodeType&&/\S/.test(b[f].nodeValue)&&(d?b[f].nodeValue="":(b[f].nodeValue=
e[h],d=!0));d||(b=l.createTextNode(e[h]),c.insertBefore(b,c.firstChild))}delete e[h]}for(var k in e)c[k]=e[k]}else console.warn("#"+b+" is undefined.")}function v(c){for(var b=(c=c||l.documentElement)?c.querySelectorAll("*[data-l10n-id]"):[],e=b.length,d=0;d<e;d++)u(b[d]);u(c)}var f={},g="",h="textContent",k="",n={},m="loading",y=!0;n.plural=function(c,b,e,d){b=parseFloat(b);if(isNaN(b)||d!=h)return c;n._pluralRules||(n._pluralRules=B(k));var a="["+n._pluralRules(b)+"]";0===b&&e+"[zero]"in f?c=f[e+
"[zero]"][d]:1==b&&e+"[one]"in f?c=f[e+"[one]"][d]:2==b&&e+"[two]"in f?c=f[e+"[two]"][d]:e+a in f?c=f[e+a][d]:e+"[other]"in f&&(c=f[e+"[other]"][d]);return c};return{get:function(c,b,e){var d=c.lastIndexOf("."),a=h;0<d&&(a=c.substr(d+1),c=c.substring(0,d));var f;e&&(f={},f[a]=e);return(b=t(c,b,f))&&a in b?b[a]:"{{"+c+"}}"},getData:function(){return f},getText:function(){return g},getLanguage:function(){return k},setLanguage:function(c,b){A(c,function(){b&&b();v()})},getDirection:function(){return 0<=
["ar","he","fa","ps","ur"].indexOf(k.split("-",1)[0])?"rtl":"ltr"},translate:v,getReadyState:function(){return m},ready:function(c){c&&("complete"==m||"interactive"==m?w.setTimeout(function(){c()}):l.addEventListener&&l.addEventListener("localized",function e(){l.removeEventListener("localized",e);c()}))}}}(window,document);
