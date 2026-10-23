//! Synthetic, reproducible multilingual corpus (shared by `grid-mapbuild`, the dev map and the simulator): short profile-like sentences built from
//! templates × fillers (jobs, hobbies, services, places) in FR, EN, ES, DE.

use rand::seq::SliceRandom;
use rand::Rng;
use rand_chacha::ChaCha20Rng;

const JOBS: &[&str] = &[
    "software developer",
    "hairdresser",
    "plumber",
    "math teacher",
    "nurse",
    "architect",
    "baker",
    "lawyer",
    "photographer",
    "electrician",
    "graphic designer",
    "accountant",
    "chef",
    "dentist",
    "gardener",
    "translator",
    "mechanic",
    "yoga instructor",
    "real estate agent",
    "data scientist",
    "développeur logiciel",
    "coiffeur",
    "plombier",
    "professeur de maths",
    "infirmière",
    "architecte",
    "boulanger",
    "avocat",
    "photographe",
    "électricien",
    "graphiste",
    "comptable",
    "cuisinier",
    "dentiste",
    "jardinier",
    "traducteur",
    "mécanicien",
    "professeur de yoga",
    "agent immobilier",
    "data scientist",
    "desarrollador de software",
    "peluquero",
    "fontanero",
    "profesor de matemáticas",
    "enfermera",
    "arquitecto",
    "panadero",
    "abogado",
    "fotógrafo",
    "electricista",
    "Softwareentwickler",
    "Friseur",
    "Klempner",
    "Mathelehrer",
    "Krankenschwester",
    "Architekt",
    "Bäcker",
    "Anwalt",
    "Fotograf",
    "Elektriker",
];
const HOBBIES: &[&str] = &[
    "astronomy",
    "hiking",
    "chess",
    "jazz piano",
    "sailing",
    "pottery",
    "marathon running",
    "birdwatching",
    "board games",
    "climbing",
    "astronomie",
    "randonnée",
    "échecs",
    "piano jazz",
    "voile",
    "poterie",
    "marathon",
    "ornithologie",
    "jeux de société",
    "escalade",
    "astronomía",
    "senderismo",
    "ajedrez",
    "vela",
    "cerámica",
    "Astronomie",
    "Wandern",
    "Schach",
    "Segeln",
    "Keramik",
];
const SERVICES: &[&str] = &[
    "home visits",
    "online lessons",
    "emergency repairs",
    "weekend appointments",
    "free quotes",
    "same-day delivery",
    "group classes",
    "consulting for startups",
    "visites à domicile",
    "cours en ligne",
    "dépannage d'urgence",
    "rendez-vous le week-end",
    "devis gratuit",
    "livraison le jour même",
    "cours collectifs",
    "visitas a domicilio",
    "clases en línea",
    "reparaciones urgentes",
    "Hausbesuche",
    "Online-Unterricht",
    "Notfallreparaturen",
];
const PLACES: &[&str] = &[
    "Paris",
    "Lyon",
    "Marseille",
    "Bordeaux",
    "Berlin",
    "Madrid",
    "Barcelona",
    "London",
    "Brussels",
    "Montréal",
    "Genève",
    "République",
    "Belleville",
    "Le Marais",
];

const TEMPLATES: &[&str] = &[
    "{job}",
    "Experienced {job}",
    "{job} in {place}",
    "{job} passionate about {hobby}",
    "Passionate about {hobby}",
    "{hobby} enthusiast",
    "Offers {service}",
    "{job} offering {service}",
    "{job} near {place}, {service}",
    "Looking for a {job}",
    "Freelance {job}",
    "{job} à {place}",
    "{job} passionné par {hobby}",
    "Propose {service}",
    "{job} près de {place}",
    "Amateur de {hobby}",
    "{job} en {place}",
    "{job} apasionado por {hobby}",
    "{job} in {place} mit {service}",
];

pub fn generate(rng: &mut ChaCha20Rng, n: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = TEMPLATES.choose(rng).unwrap();
        let mut s = t.to_string();
        s = s.replace("{job}", JOBS.choose(rng).unwrap());
        s = s.replace("{hobby}", HOBBIES.choose(rng).unwrap());
        s = s.replace("{service}", SERVICES.choose(rng).unwrap());
        s = s.replace("{place}", PLACES.choose(rng).unwrap());
        if rng.gen_bool(0.2) {
            s = format!("{s}, {}", HOBBIES.choose(rng).unwrap());
        }
        let mut c = s.chars();
        if let Some(f) = c.next() {
            s = f.to_uppercase().collect::<String>() + c.as_str();
        }
        out.push(s);
    }
    out
}
