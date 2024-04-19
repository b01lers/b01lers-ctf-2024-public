// Taken from https://blog.kevinchisholm.com/javascript/node-js/getting-started-with-the-uglify-js-node-js-module/

//get a reference to the file system module
var fs = require('fs');

//get a reference to the uglify-js module
var JavaScriptObfuscator = require('javascript-obfuscator');


let code = fs.readFileSync('safe.js', 'utf8');;
console.log(code);

let option = {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.75,
    deadCodeInjection: false,
    deadCodeInjectionThreshold: 0.4,
    debugProtection: true,
    debugProtectionInterval: 1,
    disableConsoleOutput: false,
    domainLock: [],
    domainLockRedirectUrl: 'about:blank',
    forceTransformStrings: [],
    identifierNamesCache: null,
    identifierNamesGenerator: 'hexadecimal',
    identifiersDictionary: [],
    identifiersPrefix: '',
    ignoreImports: false,
    inputFileName: '',
    log: false,
    numbersToExpressions: false,
    optionsPreset: 'default',
    renameGlobals: true,
    renameProperties: false,
    renamePropertiesMode: 'safe',
    reservedNames: ["addToPassword", "clearPassword", "deletePassword"],
    reservedStrings: [],
    seed: 0,
    selfDefending: true,
    simplify: true,
    sourceMap: false,
    sourceMapBaseUrl: '',
    sourceMapFileName: '',
    sourceMapMode: 'separate',
    sourceMapSourcesMode: 'sources-content',
    splitStrings: true,
    splitStringsChunkLength: 10,
    stringArray: true,
    stringArrayCallsTransform: true,
    stringArrayCallsTransformThreshold: 0.5,
    stringArrayEncoding: [],
    stringArrayIndexesType: [
        'hexadecimal-number'
    ],
    stringArrayIndexShift: true,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayWrappersCount: 1,
    stringArrayWrappersChainedCalls: true,
    stringArrayWrappersParametersMaxCount: 2,
    stringArrayWrappersType: 'variable',
    stringArrayThreshold: 0.75,
    target: 'browser',
    transformObjectKeys: false,
    unicodeEscapeSequence: false
} 

//get a reference to the minified version of safe.js
var result = JavaScriptObfuscator.obfuscate(code, option);

//view the output
console.log(result.getObfuscatedCode());

fs.writeFile(__dirname+"/static/safe.js", result.getObfuscatedCode(), function(err) {
    if(err) {
        console.log(err);
    } else {
        console.log("File was successfully saved.");
    }
});
