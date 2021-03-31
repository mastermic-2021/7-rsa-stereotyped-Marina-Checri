/**
Copyright 2021 cryptoflop.org
Gestion des changements de mots de passe.
**/
randompwd(len) = {
  externstr(Str("base64 /dev/urandom | head -c ",len))[1];
}
dryrun=1;
sendmail(address,subject,message) = {
  cmd = strprintf("echo %d | mail -s '%s' %s",message,subject,address);
  if(dryrun,print(cmd),system(cmd));
}
chpasswd(user,pwd) = {
  cmd = strprintf("yes %s | passwd %s",pwd,user);
  if(dryrun,print(cmd),system(cmd));
}
template = {
  "Cher collaborateur, votre nouveau mot de passe est %s. "
  "Merci de votre comprehension, le service informatique.";
  }
change_password(user,modulus,e=7) = {
  iferr(
    pwd = randompwd(10);
    chpasswd(user, pwd);
    address = strprintf("%s@cryptoflop.org",user);
    mail = strprintf(template, pwd);
    m = fromdigits(Vec(Vecsmall(mail)),128);
    c = lift(Mod(m,modulus)^e);
    sendmail(address,"Nouveau mot de passe",c);
    print("[OK] changed password for user ",user);
  ,E,print("[ERROR] ",E));
}




/* ****************************************************************************** */
/* ******************************* Explications : ******************************* */
/* ****************************************************************************** */

/*
 * Le mail envoyé est chiffré, certes, mais une partie du clair de ce mail est connue.
 * Aussi, on veut essayer de déchiffrer l'ensemble du mail à partir des informations
 * obtenues en observant la partie correspondante du clair connue au chiffré :
 * on a une partie x inconnue, qui est entourée de deux messages m et m' :
    * clair = m || x || m';
    * chiffré = (clair)^e [n].
 * Et on cherche à déterminer cette partie x, donc à déchiffrer l'entièreté du message.
 
 * Pour ce faire, nous allons utiliser, comme l'indication le suggère, la méthode de Copersmith,
 * en nous aidant de la fonction zncoppersmith(P, N, X, {B=N}) de Pari GP.
 * Cette méthode s'applique pour (#x) et e petits, ce qui est le cas ici.

 * zncoppersmith(P, N, X, {B=N}): finds all integers x with |x| <= X such that 
   gcd(N, P(x)) >= B. X should be smaller than exp((log B)^2 / (deg(P) log N)).

*/

/*
 * Principe de la méthode de Coppersmith :
 * Elle permet de déterminer les petites racines modulaires d'un polynôme à une variable
   (ainsi que les petites racines entières d'un polynôme à deux variables).

 * Soit N un entier positif et f un polynome de degré d à coefficients dans Z :
 * f(x) = somme a_i *x^i, i de 1 à n.
 * Le problème de la petite racine modulaire consiste à trouver un entier x0 tel que
 * f(x0) = 0[N], et |x0|<B, où B est une borne fixée.

 * Nota Bene. La méthode de Coppersmith permet de transformer l'équation modulaire f_b(x0)≡0[b]
   en une équation entière f(x)=0.

*/


/* ****************************************************************************** */
/* ******************************** Fonctions : ********************************* */
/* ****************************************************************************** */


encode(m) = {
	  fromdigits(Vec(Vecsmall(m)),128);
};

decode(c) = {
	  Strchr(digits(c,128));
};

get_vec_from_string(s) = Vec(Vecsmall(s));


recuperer_message_type()={
	my(m,m_,inconnue);
	m  = "Cher collaborateur, votre nouveau mot de passe est ";
	inconnue = Vec(0,10); \\ transforme 0 en un vecteur de dimension 10.
	m_ = ". Merci de votre comprehension, le service informatique.";

	m = get_vec_from_string(m);
	m_ = get_vec_from_string(m_);

	return ([m,inconnue,m_]);
}; \\ surement un autre moyen en utilisant template() ... ?


chiffre_message_type() ={
        my(c,c_,inconnue);
	[c,inconnue,c_] = recupere_message_type();
	c = encode(c);
	inconnue = encode(inconnue);
	c_ =encode(c_);
	return ([c,inconnue,c_]);
};



/* Méthode de Coppersmith :
 * On va donc chercher à utiliser la fonction zncoppersmith(P, N, X, {B=N}).

* Déterminons ses paramètres :
 * on a un message type m || xxxxxxxxxx || m'
 
 * P :
    *  
    * la partie inconnue est au milieu du message ;
    * nous devons donc penser à la décaler, ce qui peut se faire
    * en la multipliant par le coefficient 128^(m_) pour qu'elle se positionne au bon endroit.
    * On veut donc résoudre (encode(m) + 128^(#m_) * x)^e - chiffre_mail = 0.

  * N : on prend simplement n.

  * X :
    * Il s'agit de la borne dans la méthode de Coppersmith.
    * Ici, le mot de passe contient 10 caractères en base 128,
    * donc, le code est plus petit que 128^10 : c'est notre borne !
*/


infos_message_type() ={
        my(c,c_,inconnue);
	[c,inconnue,m_] = recuperer_message_type();
	c = concat(c, inconnue);
	c = concat(c, m_);
	c = encode(c);
	return ([c,m_]);
};


coppersmith (n,e,chiffre)={
	    my(c,m_,P,X_);
	    [c,m_]=infos_message_type();
	    P = (c + 128^(#m_)*x)^e - chiffre;
	    X_ = 128^10;
	    return (zncoppersmith(P,n,X_));
}



print_message (mdp) = {
 	    print("Cher collaborateur, votre nouveau mot de passe est ",
 	    mdp, 
 	    ". Merci de votre comprehension, le service informatique.");
  }
  
  
/* ****************************************************************************** */
/* ******************************* Application : ******************************** */
/* ****************************************************************************** */


text = readvec("input.txt");
n = text[1][1];
e = text[1][2];
chiffre = text[2];

my_m = "Cher collaborateur, votre nouveau mot de passe est ";
my_m_ = ". Merci de votre comprehension, le service informatique.";
	
[m,inconnue,m_]=recuperer_message_type();

copper = coppersmith (n, e, chiffre);
print_message(decode(copper[1]));




