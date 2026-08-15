package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"sync"

	"github.com/eraceo/Hako/internal/entropy"
	"github.com/eraceo/Hako/internal/memory"
)

// Generator Sentinel Errors
var (
	ErrInvalidLength     = errors.New("password length must be at least 4")
	ErrMissingComplexity = errors.New("password does not meet standard alphanumeric complexity")
	ErrEmptyCharset      = errors.New("character set is empty")
	ErrEmptyWordList     = errors.New("word list is empty")
)

const (
	// LowerCase contains lowercase letters for password generation.
	LowerCase = "abcdefghijklmnopqrstuvwxyz"
	// UpperCase contains uppercase letters for password generation.
	UpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	// Digits contains numeric digits for password generation.
	Digits = "0123456789"
	// Symbols contains special characters for password generation.
	Symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

	// Memorable word list (subset of EFF Short Wordlist 2).
	memorableWords = "acorn,active,actual,adapt,adjust,admire,admit,adobe,adopt,adult,advise,affect," +
		"afraid,agent,agree,ahead,aim,airport,alarm,album,alert,alien,alive,all,allow," +
		"alpha,alpine,alter,always,amaze,amazon,amber,ambush,amen,amid,among,amount," +
		"amuse,anchor,ancient,android,anger,angle,angry,animal,ankle,announce,answer," +
		"antenna,anxiety,any,apart,apology,appear,apple,approve,april,arch,arctic,area," +
		"arena,argue,arm,armed,armor,army,around,arrange,arrest,arrive,arrow,art," +
		"artifact,artist,artwork,ask,aspect,assault,asset,assist,assume,asthma,athlete," +
		"atom,attack,attend,attic,attract,auction,audit,august,aunt,author,auto,autumn," +
		"average,avocado,avoid,awake,aware,away,awesome,awful,awkward,axis,baby,bachelor," +
		"bacon,badge,bag,bait,baker,balance,ball,balloon,bamboo,banana,banner,bar,barely," +
		"bargain,barrel,base,basic,basket,batch,bath,battery,battle,beach,bean,bear," +
		"beard,beast,beat,beauty,become,beef,before,begin,behave,behind,believe,below," +
		"belt,bench,benefit,best,betray,better,between,beyond,bicycle,bid,bike,bind," +
		"biology,bird,birth,bitter,black,blade,blame,blanket,blast,bleak,blend,bless," +
		"blind,blink,block,blond,blood,bloom,blouse,blue,blur,blush,board,boat,body,boil," +
		"bomb,bone,bonus,book,boost,border,boring,borrow,boss,bottom,bounce,box,boy," +
		"bracket,brain,brand,brass,brave,bread,breeze,brick,bridge,brief,bright,bring," +
		"brisk,broccoli,broken,bronze,broom,brother,brown,brush,bubble,buddy,budget," +
		"buffalo,build,bulb,bulk,bullet,bundle,bunker,burden,burger,burst,bus,bush," +
		"butter,buzz,cab,cabin,cable,cactus,cage,cake,call,calm,camera,camp,can,canal," +
		"cancel,candy,cannon,canoe,canvas,canyon,capable,capital,captain,car,carbon,card," +
		"cargo,carpet,carry,cart,case,cash,casino,castle,casual,cat,catalog,catch," +
		"category,cattle,caught,cause,caution,cave,ceiling,celery,cement,census,century," +
		"cereal,certain,chair,chalk,champion,change,chaos,chapter,charge,chase,chat," +
		"cheap,check,cheese,chef,cherry,chest,chicken,chief,child,chimney,choice,choose," +
		"chronic,chuckle,chunk,churn,cigar,cinnamon,circle,citizen,city,civil,claim,clap," +
		"clarity,claw,clay,clean,clerk,clever,click,client,cliff,climb,clinic,clip,clock," +
		"clog,close,cloth,cloud,clown,club,clump,cluster,clutch,coach,coast,coconut,code," +
		"coffee,coil,coin,collect,color,column,combine,come,comfort,comic,common,company," +
		"concert,conduct,confirm,congress,connect,consider,control,convince,cook,cool," +
		"copper,copy,coral,core,corn,correct,cost,cotton,couch,country,couple,course," +
		"cousin,cover,coyote,crack,cradle,craft,cram,crane,crash,crater,crawl,crazy," +
		"cream,credit,creek,crew,cricket,crime,crisp,critic,crop,cross,crouch,crowd," +
		"crucial,cruel,cruise,crumble,crunch,crush,cry,crystal,cube,culture,cup,cupboard," +
		"curious,current,curtain,curve,cushion,custom,cute,cycle,dad,damage,damp,dance," +
		"danger,daring,dash,daughter,dawn,day,deal,debate,debris,debt,decade,december," +
		"decide,deck,decorate,decrease,deer,defense,define,defy,degree,delay,deliver," +
		"demand,demise,denial,dentist,deny,depart,depend,deposit,depth,deputy,derive," +
		"describe,desert,design,desk,despair,destroy,detail,detect,develop,device,devote," +
		"diagram,dial,diamond,diary,dice,diesel,diet,differ,digital,dignity,dilemma," +
		"dinner,dinosaur,direct,dirt,disagree,discover,disease,dish,dismiss,disorder," +
		"display,distance,divert,divide,divorce,dizzy,doctor,document,dog,doll,dolphin," +
		"domain,donate,donkey,donor,door,dose,double,dove,draft,dragon,drama,draw,dread," +
		"dream,dress,drift,drill,drink,drip,drive,drop,drum,dry,duck,dumb,dune,during," +
		"dust,dutch,duty,dwarf,dynamic,eager,eagle,early,earn,earth,easily,east,easy," +
		"echo,ecology,economy,edge,edit,educate,effort,egg,eight,either,elbow,elder," +
		"electric,elegant,element,elephant,elevator,elite,else,embark,embody,embrace," +
		"emerge,emotion,employ,empower,empty,enable,enact,end,endless,endorse,enemy," +
		"energy,enforce,engage,engine,enhance,enjoy,enlist,enough,enrich,enroll,ensure," +
		"enter,entire,entry,envelope,episode,equal,equip,era,erase,erode,erosion,error," +
		"erupt,escape,essay,essence,estate,eternal,ethics,evidence,evil,evoke,evolve," +
		"exact,example,excess,exchange,excite,exclude,excuse,execute,exercise,exhaust," +
		"exhibit,exile,exist,exit,exotic,expand,expect,expire,explain,expose,express," +
		"extend,extra,eye,eyebrow,fabric,face,faculty,fade,faint,faith,fall,false,fame," +
		"family,famous,fan,fancy,fantasy,farm,fashion,fat,fatal,father,fatigue,fault," +
		"favorite,feature,february,federal,fee,feed,feel,female,fence,festival,fetch," +
		"fever,few,fiber,fiction,field,figure,file,film,filter,final,find,fine,finger," +
		"finish,fire,firm,first,fiscal,fish,fit,fitness,fix,flag,flame,flash,flat,flavor," +
		"flee,flight,flip,float,flock,floor,flower,fluid,flush,fly,foam,focus,fog,foil," +
		"fold,follow,food,foot,force,forest,forget,fork,fortune,forum,forward,fossil," +
		"foster,found,fox,fragile,frame,frequent,fresh,friend,fringe,frog,front,frost," +
		"frown,frozen,fruit,fuel,fun,funny,furnace,fury,future,gadget,gain,galaxy," +
		"gallery,game,gap,garage,garbage,garden,garlic,garment,gas,gasp,gate,gather," +
		"gauge,gaze,general,genius,genre,gentle,genuine,gesture,ghost,giant,gift,giggle," +
		"ginger,giraffe,girl,give,glad,glance,glare,glass,glide,glimpse,globe,gloom," +
		"glory,glove,glow,glue,goat,goddess,gold,good,goose,gorilla,gospel,gossip,govern," +
		"gown,grab,grace,grain,grant,grape,grass,gravity,great,green,grid,grief,grit," +
		"grocery,group,grow,grunt,guard,guess,guide,guilt,guitar,gun,gym,habit,hair,half," +
		"hammer,hamster,hand,handle,hang,happen,happy,harbor,hard,harsh,harvest,hat,have," +
		"hawk,hazard,head,health,heart,heavy,hedgehog,height,hello,helmet,help,hen,hero," +
		"hidden,high,hill,hint,hip,hire,history,hobby,hockey,hold,hole,holiday,hollow," +
		"home,honey,hood,hope,horn,horror,horse,hospital,host,hotel,hour,hover,hub,huge," +
		"human,humble,humor,hundred,hungry,hunt,hurdle,hurry,hurt,husband,hybrid,ice," +
		"icon,idea,identify,idle,ignore,ill,illegal,illness,image,imitate,immerse,immune," +
		"impact,imply,improve,impulse,inch,include,income,increase,index,indicate,indoor," +
		"industry,infant,inflict,inform,inhale,inherit,initial,inject,injury,inmate," +
		"inner,innocent,input,inquiry,insane,insect,inside,inspire,install,intact," +
		"interest,into,invest,invite,involve,iron,island,isolate,issue,item,ivory,jacket," +
		"jaguar,jar,jazz,jealous,jeans,jelly,jewel,job,join,joke,jolly,journey,joy,judge," +
		"juice,jump,jungle,junior,junk,just,kangaroo,keen,keep,ketchup,key,kick,kid," +
		"kidney,kind,kingdom,kiss,kit,kitchen,kite,kitten,kiwi,knee,knife,knock,know,lab," +
		"label,labor,ladder,lady,lake,lamp,language,laptop,large,later,latin,laugh," +
		"laundry,lava,law,lawn,lawsuit,layer,lazy,leader,leaf,learn,leave,lecture,left," +
		"leg,legal,legend,leisure,lemon,lend,length,lens,leopard,lesson,letter,level," +
		"liar,liberty,library,license,life,lift,light,like,limb,limit,link,lion,liquid," +
		"list,little,live,lizard,load,loan,lobster,local,lock,logic,lonely,long,loop," +
		"lottery,loud,lounge,love,loyal,lucky,luggage,lumber,lunar,lunch,luxury,lyrics," +
		"machine,mad,magic,magnet,maid,mail,main,major,make,mammal,man,manage,mandate," +
		"mango,mansion,manual,maple,marble,march,margin,marine,market,marriage,mask,mass," +
		"master,match,material,math,matrix,matter,maximum,maze,meadow,mean,measure,meat," +
		"mechanic,medal,media,melody,melt,member,memory,mention,menu,mercy,merge,merit," +
		"merry,mesh,message,metal,method,middle,midnight,milk,million,mimic,mind,minimum," +
		"minor,minute,miracle,mirror,misery,miss,mistake,mix,mixed,mixture,mobile,model," +
		"modify,mom,moment,monitor,monkey,monster,month,moon,moral,more,morning,mosquito," +
		"mother,motion,motor,mountain,mouse,move,movie,much,muffin,mule,multiply,muscle," +
		"museum,mushroom,music,must,mutual,myself,mystery,myth,naive,name,napkin,narrow," +
		"nasty,nation,nature,near,nearest,neat,neck,need,negative,neighbor,neither,nerve," +
		"nest,net,network,neutral,never,news,next,nice,night,noble,noise,nominee,noodle," +
		"normal,north,nose,notable,note,nothing,notice,novel,now,nuclear,number,nurse," +
		"nut,oak,obey,object,oblige,obscure,observe,obtain,obvious,occur,ocean,october," +
		"odor,off,offer,office,often,oil,okay,old,olive,olympic,omit,once,one,onion," +
		"online,only,open,opera,opinion,oppose,option,orange,orbit,orchard,order," +
		"ordinary,organ,orient,original,orphan,ostrich,other,outdoor,outer,output," +
		"outside,oval,oven,over,own,owner,oxygen,oyster,ozone,pact,paddle,page,pair," +
		"palace,palm,panda,panel,panic,panther,paper,parade,parent,park,parrot,party," +
		"pass,patch,path,patient,patrol,pattern,pause,pave,payment,peace,peanut,pear," +
		"peasant,pelican,pen,penalty,pencil,people,pepper,perfect,permit,person,pet," +
		"phone,photo,phrase,physical,piano,picnic,picture,piece,pig,pigeon,pill,pilot," +
		"pink,pioneer,pipe,pistol,pitch,pizza,place,planet,plastic,plate,play,please," +
		"pledge,pluck,plug,plunge,poem,poet,point,polar,pole,police,pond,pony,pool," +
		"popular,portion,position,post,potato,pottery,poverty,powder,power,practice," +
		"praise,predict,prefer,prepare,present,pretty,prevent,price,pride,primary,print," +
		"priority,prison,private,prize,problem,process,produce,profit,program,project," +
		"promote,proof,property,prosper,protect,proud,provide,public,pudding,pull,pulp," +
		"pulse,pumpkin,punch,pupil,puppy,purchase,pure,purple,purpose,purse,push,put," +
		"puzzle,pyramid,quality,quantum,quarter,question,quick,quit,quiz,quote,rabbit," +
		"raccoon,race,rack,radar,radio,rail,rain,raise,rally,ramp,ranch,random,range," +
		"rapid,rare,rate,rather,raven,raw,razor,ready,reality,reason,rebel,build,recall," +
		"receive,recipe,record,recycle,reduce,reflect,reform,refuse,region,regret," +
		"regular,reject,relax,release,relief,rely,remain,remember,remind,remote,remove," +
		"render,renew,rent,reopen,repair,repeat,replace,reply,report,request,require," +
		"rescue,resemble,resist,resource,response,result,retire,retreat,return,reunion," +
		"reveal,review,reward,rhythm,rib,ribbon,rice,rich,ride,ridge,rifle,right,rigid," +
		"ring,riot,ripple,risk,ritual,rival,river,road,roast,robot,robust,rocket,romance," +
		"roof,rookie,room,rose,rotate,rough,round,route,royal,rubber,rude,rug,rule,run," +
		"runway,rural,sad,saddle,sadness,safe,sail,salad,salmon,salon,salt,salute,same," +
		"sample,sand,satisfy,satoshi,sauce,sausage,save,say,scale,scan,scare,scatter," +
		"scene,scheme,school,science,scissors,scoop,scout,scrap,screen,script,scrub,sea," +
		"search,season,seat,second,secret,section,security,seed,seek,segment,select,sell," +
		"seminar,senior,sense,sentence,series,service,session,settle,setup,seven,shadow," +
		"shaft,shallow,share,shed,shell,sheriff,shield,shift,shine,ship,shiver,shock," +
		"shoe,shoot,shop,short,shoulder,shove,shrimp,shrug,shuffle,shy,sibling,sick,side," +
		"siege,sight,sign,silent,silk,silly,silver,similar,simple,since,sing,siren," +
		"sister,situate,six,size,skate,sketch,ski,skill,skin,skirt,skull,slab,slam,sleep," +
		"slender,slice,slide,slight,slim,slogan,slot,slow,slush,small,smart,smile,smoke," +
		"smooth,snack,snake,snap,sniff,snow,soap,soccer,social,sock,soda,soft,solar," +
		"soldier,solid,solution,solve,someone,song,soon,sorry,sort,soul,sound,soup," +
		"source,south,space,spare,spark,speak,special,speed,spell,spend,sphere,spice," +
		"spider,spike,spin,spirit,split,spoil,sponsor,spoon,sport,spot,spray,spread," +
		"spring,spy,square,squeeze,squirrel,stable,stadium,staff,stage,stairs,stamp," +
		"stand,start,state,stay,steak,steel,stem,step,stereo,stick,still,sting,stock," +
		"stomach,stone,stool,story,stove,strategy,street,strike,strong,struggle,student," +
		"stuff,stumble,style,subject,submit,subway,success,such,sudden,suffer,sugar," +
		"suggest,suit,summer,sun,sunny,sunset,super,supply,supreme,sure,surface,surge," +
		"surprise,surround,survey,suspect,sustain,swallow,swamp,swap,swarm,swear,sweet," +
		"swift,swim,swing,switch,sword,symbol,symptom,syrup,system,table,tackle,tag,tail," +
		"talent,talk,tank,tape,target,task,taste,tattoo,taxi,teach,team,tell,ten,tenant," +
		"tennis,tent,term,test,text,thank,that,theme,then,theory,there,they,thing,this," +
		"thought,three,thrive,throw,thumb,thunder,ticket,tide,tiger,tilt,timber,time," +
		"tiny,tip,tired,tissue,title,toast,tobacco,today,toddler,toe,together,toilet," +
		"token,tomato,tomorrow,tone,tongue,tonight,tool,tooth,top,topic,topple,torch," +
		"tornado,tortoise,toss,total,tourist,toward,tower,town,toy,track,trade,traffic," +
		"tragic,train,transfer,trap,trash,travel,tray,treat,tree,trend,trial,tribe,trick," +
		"trigger,trim,trip,trophy,trouble,truck,true,truly,trumpet,trust,truth,try,tube," +
		"tuition,tumble,tuna,tunnel,turkey,turn,turtle,twelve,twenty,twice,twin,twist," +
		"two,type,typical,ugly,umbrella,unable,unaware,uncle,uncover,under,undo,unfair," +
		"unfold,unhappy,uniform,unique,unit,universe,unknown,unlock,until,unusual,unveil," +
		"update,upgrade,uphold,upon,upper,upset,urban,urge,usage,use,used,useful,useless," +
		"usual,utility,vacant,vacuum,vague,valid,valley,valve,van,vanish,vapor,various," +
		"vast,vault,vehicle,velvet,vendor,venture,venue,verb,verify,version,very,vessel," +
		"veteran,viable,vibrant,vicious,victory,video,view,village,vintage,violin," +
		"virtual,virus,visa,visit,visual,vital,vivid,vocal,voice,void,volcano,volume," +
		"vote,voyage,wage,wagon,wait,walk,wall,walnut,want,warfare,warm,warrior,wash," +
		"wasp,waste,water,wave,way,wealth,weapon,wear,weasel,weather,web,wedding,weekend," +
		"weird,welcome,west,wet,whale,what,wheat,wheel,when,where,whip,whisper,wide," +
		"width,wife,wild,will,win,window,wine,wing,wink,winner,winter,wire,wisdom,wise," +
		"wish,witness,wolf,woman,wonder,wood,wool,word,work,world,worry,worth,wrap,wreck," +
		"wrestle,wrist,write,wrong,yard,year,yellow,you,young,youth,zebra,zero,zone,zoo"
)

var (
	parsedWords     []string
	parsedWordsOnce sync.Once
)

// getWordList parses the memorableWords constant exactly once.
func getWordList() []string {
	parsedWordsOnce.Do(func() {
		parsedWords = strings.Split(memorableWords, ",")
	})
	return parsedWords
}

// GeneratorOptions contains options for password generation.
type GeneratorOptions struct {
	Length     int
	UseSymbols bool
	Memorable  bool
	NoSimilar  bool // Exclude similar characters (0, O, l, 1, etc.)
}

// DefaultGeneratorOptions returns sensible defaults.
func DefaultGeneratorOptions() GeneratorOptions {
	return GeneratorOptions{
		Length:     16,
		UseSymbols: true,
		Memorable:  false,
		NoSimilar:  false,
	}
}

// GeneratePassword generates a secure password based on options.
func GeneratePassword(opts GeneratorOptions) ([]byte, error) {
	if opts.Memorable {
		return generateMemorablePassword(opts)
	}
	return generateRandomPassword(opts)
}

// generateRandomPassword generates a random password guaranteed to meet complexity rules.
func generateRandomPassword(opts GeneratorOptions) ([]byte, error) {
	if opts.Length < 4 {
		return nil, ErrInvalidLength
	}

	// Build the full allowable charset
	charset := buildCharsetBytes(opts)
	if len(charset) == 0 {
		return nil, ErrEmptyCharset
	}

	password := make([]byte, opts.Length)

	// SECURITY: Ensure we wipe the password buffer on any error return
	success := false
	defer func() {
		if !success {
			memory.SecureZero(password)
		}
	}()

	// Fill with random characters from the charset
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < opts.Length; i++ {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return nil, fmt.Errorf("crypto/rand error: %w", err)
		}
		password[i] = charset[idx.Int64()]
	}

	// Force Injection of Required Complexity Classes
	// Overwrite random positions with required chars to guarantee complexity in O(1).
	requiredClasses := [][]byte{
		[]byte(LowerCase),
		[]byte(UpperCase),
		[]byte(Digits),
	}
	if opts.UseSymbols {
		requiredClasses = append(requiredClasses, []byte(Symbols))
	}

	// Shuffle the positions we will overwrite to avoid pattern
	indices := make([]int, opts.Length)
	for i := range indices {
		indices[i] = i
	}

	// Fisher-Yates shuffle for indices using CSPRNG
	maxLimit := new(big.Int)
	for i := len(indices) - 1; i > 0; i-- {
		maxLimit.SetInt64(int64(i + 1))
		jBig, err := rand.Int(rand.Reader, maxLimit)
		if err != nil {
			return nil, err
		}
		j := int(jBig.Int64())
		indices[i], indices[j] = indices[j], indices[i]
	}

	// Inject required characters
	for i, class := range requiredClasses {
		if i >= len(indices) {
			break // Should not happen given MinLength=4 check
		}

		validChars := class
		if opts.NoSimilar {
			validChars = filterSimilar(class)
		}

		if len(validChars) == 0 {
			continue // Skip if class is empty after filtering
		}

		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(validChars))))
		if err != nil {
			return nil, err
		}

		pos := indices[i]
		password[pos] = validChars[charIndex.Int64()]
	}

	success = true
	return password, nil
}

// filterSimilar removes ambiguous characters from a byte slice.
// Uses a switch statement to be strictly Zero-Allocation and O(N).
func filterSimilar(chars []byte) []byte {
	filtered := make([]byte, 0, len(chars))
	for _, b := range chars {
		switch b {
		case '0', 'O', '1', 'l', 'I', '|':
			continue
		default:
			filtered = append(filtered, b)
		}
	}
	return filtered
}

// buildCharsetBytes builds the character set safely as a byte slice.
func buildCharsetBytes(opts GeneratorOptions) []byte {
	size := len(LowerCase) + len(UpperCase) + len(Digits)
	if opts.UseSymbols {
		size += len(Symbols)
	}

	charset := make([]byte, 0, size)
	charset = append(charset, LowerCase...)
	charset = append(charset, UpperCase...)
	charset = append(charset, Digits...)
	if opts.UseSymbols {
		charset = append(charset, Symbols...)
	}

	if opts.NoSimilar {
		return filterSimilar(charset)
	}

	return charset
}

// generateMemorablePassword generates a memorable passphrase using words.
func generateMemorablePassword(opts GeneratorOptions) ([]byte, error) {
	words := getWordList()
	if len(words) == 0 {
		return nil, ErrEmptyWordList // Used Sentinel Error
	}
	wordsLen := big.NewInt(int64(len(words)))

	// Minimum 3 words for security (~35 bits entropy minimum)
	numWords := opts.Length
	if numWords < 3 {
		numWords = 3
	}
	// Cap at 10 words to prevent abuse/DoS
	if numWords > 10 {
		numWords = 10
	}

	password := make([]byte, 0, numWords*8)
	success := false
	defer func() {
		if !success {
			memory.SecureZero(password)
		}
	}()

	separators := []byte{'-', '_', '.', '!'}
	if !opts.UseSymbols {
		separators = []byte{'-', '_'}
	}
	sepLen := big.NewInt(int64(len(separators)))

	// Pick one separator for the whole phrase (standard practice)
	sepIndex, err := rand.Int(rand.Reader, sepLen)
	if err != nil {
		return nil, fmt.Errorf("separator rand error: %w", err)
	}
	separator := separators[sepIndex.Int64()]

	for i := 0; i < numWords; i++ {
		if i > 0 {
			password = append(password, separator)
		}

		wordIndex, err := rand.Int(rand.Reader, wordsLen)
		if err != nil {
			return nil, fmt.Errorf("word rand error: %w", err)
		}

		wordStr := words[wordIndex.Int64()]
		password = append(password, wordStr...)
	}

	// Add random numeric suffix (2 digits) to increase entropy against dictionary attacks
	for i := 0; i < 2; i++ {
		digit, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return nil, fmt.Errorf("digit rand error: %w", err)
		}
		// #nosec G115 -- digitIndex is guaranteed [0,9] by big.NewInt(10) bound, byte conversion is safe
		password = append(password, '0'+byte(digit.Int64()))
	}

	success = true
	return password, nil
}

// GenerateKeyfile generates a cryptographically secure sequence of random bytes.
func GenerateKeyfile(size int) ([]byte, error) {
	if size < 32 {
		size = 32 // Enforce minimum 256-bit entropy
	}

	keyfile := make([]byte, size)

	success := false
	defer func() {
		if !success {
			memory.SecureZero(keyfile)
		}
	}()

	if _, err := rand.Read(keyfile); err != nil {
		return nil, fmt.Errorf("failed to generate keyfile: %w", err)
	}

	success = true
	return keyfile, nil
}

// CalculateEntropy estimates the theoretical maximum entropy of the generator configuration.
func (opts GeneratorOptions) CalculateEntropy() float64 {
	if opts.Memorable {
		words := getWordList()
		if len(words) == 0 {
			return 0
		}

		wordEntropy := math.Log2(float64(len(words)))
		numWords := float64(opts.Length)
		if numWords < 3 {
			numWords = 3
		}

		extrasEntropy := 6.64 // 2 digits
		if opts.UseSymbols {
			extrasEntropy += 2.0 // 4 separators
		} else {
			extrasEntropy += 1.0 // 2 separators
		}

		return numWords*wordEntropy + extrasEntropy
	}

	poolSize := 0
	poolSize += 26 // Lower
	poolSize += 26 // Upper
	poolSize += 10 // Digits
	if opts.UseSymbols {
		poolSize += len(Symbols)
	}

	if opts.NoSimilar {
		poolSize -= 6
	}

	if poolSize <= 0 {
		return 0
	}

	return float64(opts.Length) * math.Log2(float64(poolSize))
}

// CalculateActualEntropy calculates entropy of a generated password using the entropy package.
func CalculateActualEntropy(password []byte) float64 {
	return entropy.Calculate(password)
}
