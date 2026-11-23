// A key's everyday name: two words made from its address, the same in every app that uses this list
// (the compute-substrate kit has the same one), so a key that never chose a name still reads as
// someone, not as hex. It's a convenience, not proof: anyone can make keys until one gets the same
// two words, so the address stays where it matters (a profile, anything that moves CSD).
const ADJ = ("amber,ancient,arctic,ashen,autumn,azure,bold,brave,breezy,bright,brisk,bronze,calm,candid,carmine,cedar," +
  "chalk,cheerful,clever,cloudy,cobalt,copper,coral,cosmic,crimson,crisp,curious,dapper,daring,dawn,deep,dusky," +
  "eager,early,earnest,ebony,electric,elder,emerald,even,fair,fallow,feathered,fern,fervent,fiery,flint,floral," +
  "fluent,foggy,frank,frosty,gallant,gentle,gilded,glacial,gleaming,golden,graceful,granite,grassy,green,hardy,hazel," +
  "hidden,hollow,honest,humble,icy,indigo,inland,iron,ivory,jade,jolly,keen,kind,lapis,late,lavender," +
  "leafy,lemon,lilac,limber,lively,lone,lucid,lucky,lunar,maple,marble,meadow,mellow,merry,midnight,mild," +
  "misty,modest,mossy,muted,nimble,noble,north,oaken,ocean,olive,onyx,opal,orchid,pale,patient,pearl," +
  "pebble,pine,plain,plucky,polar,proud,quick,quiet,rapid,rare,ready,regal,restful,river,rocky,rosy," +
  "royal,ruby,rustic,sable,saffron,sage,salty,sandy,scarlet,serene,shady,sharp,shining,silent,silver,simple," +
  "sleek,slow,smoky,snowy,solar,solid,sober,south,spare,spry,starry,steady,stone,stormy,sturdy,sunny," +
  "swift,tall,tawny,tender,thistle,tidal,timber,tranquil,true,twilight,umber,upland,valiant,velvet,vernal,violet," +
  "vivid,warm,wary,wild,windy,winter,wise,witty,wooden,woolly,young,zealous,zesty,amiable,balmy,bashful," +
  "blithe,boreal,bramble,brindle,buoyant,canny,cinder,clover,coastal,dappled,dewy,dune,dusty,elfin,fabled,fawn," +
  "fleet,frugal,gusty,harbor,heather,hearty,highland,honeyed,jasper,kindly,lanky,lofty,mirthful,nomad,nutmeg,orange," +
  "pastel,peppy,prairie,quaint,radiant,russet,rugged,sepia,spruce,stellar,sylvan,teal,thrifty,topaz,verdant,wandering," +
  "agile,airy,briny,burnished,citrine,dauntless,dreamy,feral,frosted,glossy,hushed,limpid,moonlit,placid,sunlit,tidy").split(",");
const NOUN = ("acorn,alder,anchor,antler,apple,arch,aspen,badger,basin,bay,beacon,bear,beaver,bee,birch,bison," +
  "bloom,boulder,bramble,brook,buck,canyon,cardinal,cedar,cliff,cloud,comet,condor,coral,cormorant,cove,crane," +
  "creek,crow,dale,deer,delta,dolphin,dove,dune,eagle,egret,elk,elm,ember,falcon,fern,finch," +
  "fjord,flame,fox,frog,gale,garnet,gazelle,geyser,glade,glen,goose,grove,gull,hare,harbor,hawk," +
  "heath,heron,hill,hollow,horizon,ibis,island,ivy,jay,juniper,kestrel,kite,lake,lantern,lark,laurel," +
  "leaf,lily,linden,lion,lynx,magpie,mallard,maple,marsh,meadow,mesa,mink,moon,moose,moss,moth," +
  "nest,newt,nightjar,oak,ocelot,orca,oriole,osprey,otter,owl,panther,pebble,pelican,pepper,petrel,pike," +
  "pine,plover,pond,poplar,prairie,puffin,quail,quartz,rain,raven,reed,ridge,river,robin,rook,rowan," +
  "sage,salmon,sand,sparrow,spring,spruce,star,stoat,stone,stork,stream,summit,swallow,swan,swift,sycamore," +
  "tern,thicket,thistle,thrush,tide,tiger,trail,trout,tulip,tundra,valley,vine,vole,walrus,warbler,wave," +
  "willow,wolf,wren,yarrow,yew,zephyr,abbey,amber,arbor,aurora,bluff,brier,cairn,cascade,cinder,clover," +
  "cobble,crest,cypress,dahlia,dawn,dusk,estuary,fennel,fescue,firefly,flint,floe,glacier,gorge,granite,gully," +
  "hazel,hedge,hemlock,hyacinth,iris,jackal,jasmine,kelp,knoll,lagoon,larch,ledge,lichen,lotus,marten,meteor," +
  "mistral,nebula,nettle,oasis,orchid,peak,pinion,plume,quill,rapids,reef,saffron,savanna,shoal,sierra,sorrel," +
  "spire,squall,steppe,sumac,talon,thyme,timber,torrent,umber,vale,verbena,violet,whirl,wisteria,yucca,zinnia," +
  "albatross,bobcat,caribou,chamois,coyote,falconet,grouse,heronry,ibex,lemming,marmot,narwhal,pika,skylark,sandpiper,wombat").split(",");

export function friendlyName(addr: string): string {
  const h = addr.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(h)) return addr;
  // from the address's last bytes, which are as random as any
  return `${ADJ[parseInt(h.slice(-4, -2), 16) % ADJ.length]}-${NOUN[parseInt(h.slice(-2), 16) % NOUN.length]}`;
}
