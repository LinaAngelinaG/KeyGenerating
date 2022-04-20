import HMAC.HMAC;
import KeyGenerating.HKDF;
import KeyGenerating.PBKDF2;

import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.BitSet;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        HKDF hkdf = new HKDF();
        PBKDF2 pbkdf2 = new PBKDF2();
        System.out.println("HKDF\n");
        HMAC h = new HMAC();
        SecureRandom random = new SecureRandom();
        byte salt[] = new byte[32];
        double[] data = {339.7,  339. ,  338. ,  336.1,  333.7,  332.4,  333.2,  335. ,  336.8,  338. ,  339. ,  339.6,  339.4,  338.9,  338.6,  339.1,  339.9,  340.5,  340.3,  339.8,  339.3,  339. ,  338.7,  338.8,  339.7,  340.9,  342.4,  344. ,  345.8,  347.7,  349.7,  351.9,  353.9,  355.6,  357.2,  358.9,  360.8,  362.8,  364.1,  364. ,  363.3,  363.1,  364.2,  365.7,  366.9,  367.2,  367.2,  367.9,  370. , 1018.6, 1018.7, 1018.9, 1019. , 1019.1, 1019.2, 1019.1, 1019.1, 1019.5, 1020.1, 1020.9, 1021.3, 1021. , 1020.4, 1020.3, 1019.9, 1019. , 1018.9, 1019.2, 1019.6, 1019.5, 1019.8, 1020.3, 1020.6, 1020.5, 1020.3, 1020.1, 1019.9, 1019.8, 1019.8, 1019.8, 1020.1, 1020.3, 1020.6, 1020.9, 1021.1, 1020.9, 1020.5, 1019.4, 1018.8, 1018.8, 1018.5, 1018.6, 1018.3, 1018.7, 1018.9, 1019.6, 1019.6, 1019.6};
        for(int i = 0; i < 1000; ++i){
            String s = data.toString();
            random.nextBytes(salt);
            byte[] res = hkdf.KDF(salt,data.toString().getBytes(), "Angelina".getBytes(),64);
            BitSet set = BitSet.valueOf(Arrays.copyOf(res,1));
            System.out.println(toInt(set.get(0,10)));
        }
        String[] passwords = {"hemorrhoidals", "kumiss", "outdazzles", "shavetail", "scraggily", "misemphasize", "botanizing", "bonefishes", "items", "nugget", "megillas", "headroom", "lacunae", "hydrocracked", "miaoued", "awesomeness", "gastrotrichs", "meatiest", "freewill", "baaed", "harken", "multiplexer", "pastimes", "anovulants", "diverse", "bolter", "cosmologies", "tawed", "trustee", "indoles", "chazzanim", "fleury", "cunctator", "stairs", "perceptually", "lipide", "cuttage", "loxodrome", "viscidities", "preinformed", "gemminesses", "waterfowl", "kartings", "purpose", "haole", "neighbors", "counterstate", "topples", "claustrophobe", "bumkin", "groundbreaker", "ethicalnesses", "gensengs", "fretsaw", "inanimately", "seedsmen", "distrusted", "sinuations", "lustrate", "cacographical", "painkillers", "undersign", "modalities", "remarks", "reprieve", "trouped", "megapodes", "reorders", "enlargements", "resiliency", "fabled", "readings", "dippable", "masseter", "chalkboard", "dismissal", "waspy", "himations", "thrusting", "entases", "cruor", "tattinesses", "astrocytic", "diner", "modicums", "bluetongue", "transducing", "sporulations", "incendiarism", "enterococcus", "revetted", "sprucenesses", "nonpostal", "unhair", "duiker", "inspects", "yowies", "writer", "probating", "menacers", "dewlap", "grated", "phytogeography", "downslide", "inurnment", "crispiness", "robotizations", "vigilantism", "diphthongize", "italianate", "sissinesses", "capsicums", "delousing", "mascot", "queazier", "preceptorials", "tray", "shalloon", "epicureans", "fruitcake", "journalizers", "engraved", "porters", "hole", "preinforms", "syrups", "syncretized", "barnstormer", "pulverizing", "acceptances", "relativisms", "tourism", "enterococcal", "megaliths", "footy", "culminations", "eroticists", "motte", "rekeys", "disentitled", "phagedena", "straggled", "wappenschawings", "dismal", "ureide", "casteisms", "gopher", "trolleying", "identified", "charcoal", "jellify", "armamentarium", "unwaning", "physicking", "habituating", "jewelries", "jukebox", "codiscoverers", "hematic", "bicolours", "easier", "rhachis", "jackboot", "diphthongs", "fanaticisms", "uncertainnesses", "fibre", "poppy", "dissertations", "cantrips", "sepulchre", "brassy", "harijan", "paradisial", "indicias", "laics", "supersaturate", "cytochemistry", "unisexes", "cubitus", "duckier", "forciblenesses", "sleazebag", "fleshings", "adulteresses", "rampant", "vaporings", "mimers", "predawn", "renationalize", "vims", "clearances", "quivers", "frizzing", "synchronical", "epoxying", "liquidizing", "underthrusting", "cotrustees", "breakfronts", "salvoed", "prussianises", "perfectivities", "damnable", "kiblas", "dented", "hippopotamuses", "bring", "repledges", "neuroblastomas", "egests", "involve", "misword", "oppressors", "measurer", "personalised", "generalized", "exhumation", "counteroffer", "barrenness", "dang", "brigadier", "eyewash", "nostocs", "euphemize", "toning", "kitschify", "titration", "aloneness", "hoodie", "grabber", "italianised", "brachiator", "unsling", "disomic", "otalgy", "melancholiacs", "the", "grecized", "kana", "requirer", "cirrous", "plecopterans", "desalinations", "horologic", "neist", "fixatifs", "enjambed", "pechans", "exploratory", "invade", "stey", "choicenesses", "groszy", "landmarking", "impotents", "vagrant", "shadinesses", "calqued", "hardasses", "surfboarder", "hagriders", "reddest", "movabilities", "springwood", "unstintingly", "fulminating", "sahiwal", "brees", "speediness", "phantom", "coder", "painter", "reutters", "regencies", "outtrades", "organicism", "ascensive", "roan", "meliorist", "broaden", "hist", "skulk", "fancily", "manipulated", "capfuls", "unsoured", "linguistical", "exemplar", "tallest", "compere", "gauleiters", "males", "overcontrol", "frontward", "urethroscopes", "indestructible", "naloxone", "pavan", "badder", "sporulating", "miscreant", "schnorkeling", "antistudent", "panel", "squattily", "scrimper", "proudhearted", "mainlanders", "ferrimagnetic", "colonizes", "sectilities", "creamed", "tyrannises", "basilicae", "zincing", "bacillus", "monogenies", "lacquerware", "coastwise", "ikebana", "nonbeliefs", "crewnecks", "epicardial", "reorder", "railroading", "hawsers", "griseofulvins", "annal", "langsyne", "snickerers", "dedicated", "pierces", "turps", "anemometers", "paginating", "deodorization", "fellowship", "commixture", "enlisting", "secretary", "rephrased", "dalliance", "clepsydras", "erects", "streaking", "timbermen", "miff", "royalists", "codesigning", "villenage", "undermining", "cockering", "electroscope", "electroplating", "amicus", "trouncer", "flexibility", "hyperviscosity", "communization", "creates", "fibrannes", "reconvenes", "rudiment", "mesopauses", "astrocytomata", "hander", "glaring", "unpractical", "educates", "irrationals", "lienable", "dilled", "boatbuilders", "sonorants", "tincture", "cheap", "timescales", "lemony", "flotages", "geomorphology", "metasequoia", "sporulate", "terrorism", "micturitions", "ridgetops", "photolytic", "redoing", "northwestward", "runback", "cataphoras", "disrooting", "illiberalness", "partialities", "epithetic", "fault", "stemma", "nurl", "muslins", "cornhuskings", "jaywalker", "victualling", "echoer", "straitjacketed", "french", "auspicating", "proponed", "septical", "caciques", "hypethral", "jaculates", "equipages", "hypersecretion", "leaseholds", "reoccupies", "tessellating", "microcapsules", "dolomitized", "vesuvians", "particularised", "percusses", "crockery", "latency", "leukocytic", "regicide", "nympha", "keybutton", "cursedness", "boracites", "demagnetizers", "arable", "funambulisms", "olio", "tangences", "furcates", "reflected", "proctodaeum", "manliest", "decemvirs", "monochasial", "xylol", "submaxillary", "psittacoses", "overcapacity", "correlator", "innumerates", "cupeler", "appetency", "dolerites", "oscillates", "castaways", "difficulties", "curiosity", "grandiosely", "karns", "mister", "lubing", "bagpiper", "corruptively", "catalytic", "unplausible", "ralph", "extrication", "neustic", "vesture", "bauxite", "eductors", "digressively", "canvases", "proa", "hypergamy", "dineros", "scrummaged", "adorn", "backfired", "dogdom", "homogenizers", "alderman", "inthralls", "stammers", "micronize", "plasmid", "conscience", "seasoners", "frilled", "uselessness", "optimizer", "birthworts", "beamlike", "tarpaulin", "sustainer", "gangbanger", "dhaks", "convect", "scillas", "pepperiness", "cubistic", "distrainors", "showstopping", "milker", "licenses", "hew", "properly", "bugleweed", "thiamines", "generated", "allyl", "lugeing", "bonniness", "bloggings", "yakking", "expenders", "pith", "cholestyramine", "cockinesses", "voiceprint", "tartlets", "sordino", "dichotomously", "available", "cannulates", "neatening", "barcarolles", "hypervirulent", "hypersaline", "urbanites", "menschy", "inundations", "woolwork", "jell", "conductance", "milliary", "motels", "forcible", "selectmen", "dilatometric", "leathered", "ruggedness", "sponsor", "skiing", "nonentries", "kickups", "pureed", "behaviorally", "nonrelativistic", "marimbas", "coaxingly", "marketabilities", "protocolled", "brainstems", "solemnization", "pain", "anorexia", "popple", "writhe", "broadbill", "dilutive", "saning", "sigmoidoscopy", "jongleurs", "slenderest", "herbalists", "uncrated", "poisoned", "hellbenders", "psychoanalyzed", "plessors", "evasive", "moneyers", "overgovern", "unperformable", "decontaminate", "tetched", "weanlings", "intuitionisms", "deasil", "phonographers", "autobiography", "octonaries", "steadfast", "nuncios", "detached", "hatchlings", "roadbed", "underflow", "handmaiden", "bramble", "assailer", "comers", "ridden", "retell", "trodden", "molarity", "anurous", "sexist", "stillroom", "selfless", "culches", "airhole", "integrationists", "snuffler", "thankfullest", "pocosins", "disarranges", "subkingdom", "marketed", "rereviewing", "goldenness", "sleets", "endospore", "backswings", "unageing", "wich", "gestaltists", "cos", "digitize", "lifebloods", "relandscaping", "bodiless", "barkier", "monism", "auditories", "ditziest", "ginners", "victualer", "quantiles", "platefuls", "wettest", "superlatively", "billiard", "nonchauvinist", "counterplayer", "indexations", "fucoidal", "assagais", "braconid", "gunrunners", "stoup", "waucht", "lusus", "streetlights", "monochasium", "submerse", "greasily", "biblicist", "travesties", "antiblack", "squashier", "viviparities", "saveloys", "malevolent", "phase", "governmental", "isobutylenes", "betrothals", "keypunch", "promotabilities", "encaustics", "deductible", "subsociety", "greenbugs", "lophophore", "algorithmically", "babysit", "sambals", "teraflops", "gustiest", "moustachio", "doth", "clergy", "neater", "ultrastructures", "exalter", "dekametres", "phospholipases", "cosmographic", "sup", "squawk", "delts", "recanes", "flashinesses", "cofavorites", "overloves", "experting", "leg", "scotching", "variegation", "faradaic", "sentinelling", "tushy", "apospories", "prefers", "tomentose", "goitrogenic", "comatula", "morrion", "whacked", "support", "redocked", "pipelike", "breakout", "knowingly", "demerging", "present", "toothed", "concertized", "skylit", "coops", "siliquose", "entertainment", "compiles", "superroad", "cribs", "primuses", "vampers", "vacuolation", "apomixes", "feelingly", "taxus", "ideologizes", "veratria", "backlogs", "diamins", "prohibitory", "disbelievers", "quipping", "oralist", "overexpanded", "phantoms", "sousliks", "sensitizer", "absolutes", "reenthroned", "apartmental", "reptilian", "spackled", "retinoblastoma", "acculturating", "trouts", "chemically", "testier", "joneses", "cantina", "prosector", "queenships", "plebes", "grubstake", "cottar", "colorizer", "overorganize", "giglet", "housewarmings", "celloidins", "histologies", "ramate", "demystifies", "canfields", "undercharges", "lightnesses", "sideritic", "flambeed", "laterite", "cableways", "eurytherm", "overmuscled", "brushland", "shantungs", "refrains", "macaco", "emporia", "copayments", "pencillers", "signature", "recurve", "photometers", "legitimizers", "machineable", "reorients", "experimenting", "mispackage", "minibuses", "antidote", "navigably", "galoot", "wrathful", "ensorcellments", "blazers", "propagandizing", "raker", "uniparous", "mistinesses", "covalency", "straphanger", "longhouses", "sauger", "preordainment", "irrelevance", "bleach", "diploidies", "documentary", "flagitiously", "agemates", "taskbars", "cystocarps", "sell", "autobahns", "anticensorship", "declaratory", "octanol", "persecutes", "spirting", "biodiversities", "dinos", "thwart", "disabusals", "steam", "juratory", "schnauzer", "almoners", "merceries", "langbeinite", "switchblade", "lifestyle", "munitioned", "pettifoggings", "glims", "halftone", "towelled", "outdoes", "dobbins", "greenbug", "roughlegs", "misoneist", "aerobicizing", "auspiciousness", "metallurgists", "telephotography", "geometrises", "superabsorbents", "additions", "tessera", "dimerization", "numbest", "tophes", "soteriologies", "futural", "cothurni", "candids", "tee", "thigmotaxes", "feoffed", "vibrions", "photodynamic", "overexerted", "invectiveness", "scraichs", "fornicated", "transfect", "skeltering", "classiest", "commissar", "scrouged", "dexterously", "poplars", "arboviruses", "exportations", "inciting", "biked", "immanentistic", "asana", "whiffers", "sclerodermata", "superimposable", "pellagra", "dazedly", "irreparableness", "incantations", "spear", "sumps", "blotty", "laxity", "forewarn", "waists", "argufy", "carmine", "overdrove", "mammal", "contractility", "stoppages", "litterateur", "insist", "ensamples", "constrictive", "sesquipedalian", "desecrators", "excessive", "opposers", "outtalk", "polytype", "unseemlinesses", "durum", "egression", "dissipate", "peaking", "signpost", "toolheads", "charactery", "uneducable", "resentments", "crammers", "inconsiderable", "nightmarish", "splotching", "myiasis", "guilloche", "snootinesses", "shoepacks", "biblicist", "redtails", "flesh", "remunerating", "vacancy", "brulot", "authorizer", "pleomorphism", "chokers", "ambergrises", "holandric", "latillas", "maddening", "finance", "glazy", "subvenes", "evicts", "subdeans", "priciest", "exuvium", "tribalists", "brunettes", "deoxidation", "workbag", "washbowls", "likely", "sarcomatous", "upswelling", "blanking", "quomodos", "veratridine", "apparentness", "defraud", "roominesses", "caseworm", "howitzer", "durums", "gliomas", "clunkier", "semens", "thawed", "talking", "officialese", "mucid", "ergograph", "applying", "nucellar", "spurts", "thiourea", "tautologies", "jade", "externalisms", "tenseness", "surrogates", "coinferring", "bimillenary", "clubbiness", "cheesing", "refastening", "screwworms", "wettability", "draw", "henry", "itchinesses", "lackluster", "riotously", "bacteriophagies", "cataphyll", "saltwort", "toluoles", "murrhine", "driverless", "writher", "legality", "gametes", "gargler", "hyperboloids", "symptomatology", "rumbly", "cunningest", "wince", "subacute", "velarized"};
        System.out.println("\n\n\n\n\n\nPBKDF2");
        for(int i = 0; i < 1000; ++i){
            byte[] res = pbkdf2.KDF(passwords[i].getBytes(),salt,64);
            BitSet set = BitSet.valueOf(Arrays.copyOf(res,1));
            System.out.println(toInt(set.get(0,10)));
        }
        System.out.println("\n\nPASSWORDS");
        for(int i = 0; i < 1000; ++i){
            BitSet set = BitSet.valueOf(Arrays.copyOf(passwords[i].getBytes(),1));
            System.out.println(toInt(set.get(0,10)));
        }
        System.out.println(passwords.length);
    }

    public static int toInt(BitSet bitSet) {
        int intValue = 0;
        for (int bit = 0; bit < bitSet.length(); bit++) {
            if (bitSet.get(bit)) {
                intValue |= (1 << bit);
            }
        }
        return intValue;
    }
}