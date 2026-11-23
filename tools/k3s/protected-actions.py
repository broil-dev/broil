#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Closed, request-bound credential operations on already prepared recipients."""
import base64
import fcntl
import gzip
import hashlib
import ipaddress
import json
import lzma
import os
from pathlib import Path
import pwd
import re
import selectors
import secrets
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import time
import urllib.request

ROOT = "/var/lib/broil/k3s"
PROFILE = ROOT + "/action-profile.json"
K3S = "/usr/local/libexec/broil-k3s"
DATA = "/var/lib/rancher/k3s"
MAXIMUM = 1048576
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
EFFECTS = False
DEADLINE = time.monotonic() + 7200
WRITERS_SETTLED = True
# Source-carried bootstrap index and official-airgap descriptor policy, each
# one xz stream in RFC 1924 base85; decoded and hash-bound before any use.
BOOT_INDEX = "{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;2}Z`b6o&Eh=?bAf%O`EN&Cv1wqW_m_lB?)Q8-{X!vF<O>seupvdE+`zUS?4tqh=v1p;|XlH&xC>M+s+i&!x^QyfaDjH7*49b8?dL?2M{rRk5cSF;#yGexq>{!Qn523<~S2cA_Us8B*HT}ZueS(sDRCd76Qu{S(=8MKwVfM!^LI(ao5-9UtVI6|9S=2v{%aXtKun+AF%_~-i&3ak%m7CxUmu%$xYXMxysRBS^S`ZWL!F6&;56Z)pt)kEd4ou>o2gao}^R&W|NxK#0mE;HmNTfASSXW7T;x_MHaz%l|wjW=@n&_G+eYgv=juaUy>Iy6y3x+crPr9$@TzcxOwMj=H|J3#ASu0BA6LI?O;rAFo6{?)6dvTG%sWNBdsl+5X&^<_wcfTY1Z?VxD|r3GSa>ipjut|7;+Tmcrm55D)Pijq#@l9|=aJs3U|f)E7UWx~D>l_AfRC5`{P&Us1_=<W8#3C(v~-^*nAoXXa*EaoOCofmZEQ`M_Omv;K0HKlsfvW8eqpqyTmrb@+JI7e%uO@cIsGwlXn4avrE%3-L^K_!GVH%w*HgZecaBCK~M@r5wc2!U-(_oSF+YZWQxMff71MG(0oen^iYH8nxeROetkJbN!PM!$kF3|oJ`^fKSSpum5o4eHDfm8y{=BMc?7;82B#%QikuDl28)#Wk6Kc!{UmLyILJO>-NvZa|`r7>9vX7N(5h*qcnf|H6U#YZg;A2jVSeHyHubr}2vvP@1#s;WFTmZoLs3<of2q61as@2Z3<7YL%y7`6GV)sqMNPoGUr6oWLyLLnw)Yv!PD4jZJdQ22r$XnxOLjq#>GmHrOis>H@BN<R;ws5y%{=d4hJAi3^Hhs+p1N5euH|r`G6y`R@?x3Bg$=4BW9K>Q*=t84t+1mf=e>>JhcdIAU*_s4LQE-G&}Xq<snk$R1+{wrtf&JMxdRJEmVk5uZQC6rKyYkb|rVxhNjyK>JwPMqF1ITBA`+w_8zFLqv;!H7)~vyxZ+kGl8Qy!E4Po1)awlz}eMrTIOuSzh~q_a|wI)0is$Og~*QRv}eodrOy^*tE~nc=JS}%VNLE|!X-^!Q($)#tyj@<N!ccES;nKjykU6!L@!j#L3Gf>&U?w$F6XLeSTfSccvp3T@Q$#tlAwJoVyqK*xTFocOe0n<kDU+y^)J1~=#0cz!&4>DGnqs(Y`NIxeq~{N7O`A(FEs`Q+&}=#Lb2&hr<Fo=zcu~L(i@640)8GRALVyPq$OD*L;FMFo{$-jUmQ@Is<=mih#fVII0l!iW&H_tsDSr?rZPod-p8st14**NXif(p5*Q&a`w>$2aC*#sumH)fB><^-G<9kY@)hj{F|MZ7rgW+1a3t*gt#K#v&>pt;9vXvSWf4L+B=UzUysUGde;N55HUn!O3hP){Iq{}j7=tN%$PuHOt@cJst<zQ;)i@vS?<Pf*Rf}xdu1&d(xdcPa{~LtKDQS<jE6j7UC60=#n<nWCED}#)>Y6LM)(U-5ts@W)%{GA%lCM1432GPl?GD)wb)3<)RAEi)VVJLpC@B$2#iEkF!xeQLXTd{V4gJC!+65Q3iorvudO@zD+|w5g74xv)heL6PCaEFe!Z+(9mnOabEt*MoQxmoea*ltA1t{M)VmIQCd}ON9GXehCux5dAk}agCKFVh@^iC>EN^zBr{YpdyabVk<X81KN$!yc_ZrE{cUhMZe!{Sb?S(>9ali)hSNrapD?R+B>4Q+^7kf;)OR5ni*R^u5+%YP<5%fN8i8$DjbnPktT%5@*e7tG1QTO`Db3KOBKgx1>tG26{-5waOXuvYh5h&W+8m9p-_y!Gz{gt5CXSZA=16Ldp!2M7!*o@r&i!~@Qe(pk&l5ESXZ8c|h;J416=*3PN9=9}sIU|((g%O(obGsV8SaS0?!vDa0ecaBK!?O<j#qC%qjDj&ziLf>9M2L$L@=o~xRP`_V2@m2LCk|r)8D5`3+F@<4Hp7O8(Rsmv-FAajoAT+i;zrynb0Q;vAhcQWK7};sJi-6}<ww$?34TpANWD9BK7dpo;%Z28TRC!?m_ukOwX%>a?G|GH<C<5&QY_m)O))QlP|IVF|H36cw;onKpgJs_nS6QeoO^N{6lqW6^a>1bMUM_+p7?w9CRR-lTS|{*ZjKSV#Cwe3q8F@SE)VFR1)ohA|nGkoA{9M+j*ai%GM=PifnPU$ft@cKJx0F>x^V(W)_I4_na&6w*56M4P@@$w7jfPiW)^sxjk=A}TM0+2G`VNRf_11^y4-LVL0mUtx<bv!9z}fK)T~uy<78tK@MmB*RaMhJ$1Lm>0c1=ag1Hs=pK(Uc3J64ToMge3cLm4;AD@4*!&(MCZ&RIwA#_KWosf-{iDh$MH@h=CQ(dbM#ZX)gMMz=ed`dcU=8_dCtE5UA6ksdnJtUk5hLidyTCO|{<8Jw0v(Wvmvq2A~(y#t#G4Y<|BD+!YEI`I+Gk&O(`AQ7+z*VRG-#oFAtjhYtIRIimFARgM-jt+;*6xYi+;KN)Owl}web;#`J%2pvS7a!GVly$orvfBr|$!`l!9Vq67Ib_nT4dey0kxCRcmfAI_J5;bN6DSI2+xO~86dwoj&bW>p?5J169Auq0;#+qQ54Y3HD*>h-8MYXcXH|3jVn@SjaLT(eHggMq#RAoo7)d45ouEA@YrH5!tnoURLz=;7=bM2RNc{8^v=o$twwGW1BR*&L7jdDBiCrhhj%L|x-h#gtRpN;oQY>HWAbtywEMvDd>%<AW_Q20-)6W7cQt3L6+d`+yc?3!cq1n<+;LK-g2=|BCQ=O9x$7l)+eJhayNSbV*l1<G6qW%h2+@Cw6$oKx{LfbN%J_YyO-Kt5Jm&Zf(9vfbN+2)~91bZxI)crPmLRj-los3V@fD*?!L|^q5E#pY)%9=+F#Mg!mrX=!*Ea@@Is$|b7-%xP;a#I)|UVRmST!DNg(x;Rx9%&?^ssi>LsDAo33Ha0QAhcz!mL_YF0F$)rvV%plZLboO1vHKtpKxhUvk#-^gQe-54^4t|*<iDhUm9X2hw!#AfAYTZ=Qf!%31=9+`X)T+_S7^uzA5byj?b3L&g*U}JIc>7ij@D|`t!Wu@F#W8p6CsrSUCEkMts#aHFLm2c#)YeaWI<rZ>Xgx2fZy;<w**YzxWSlvSTCE6r^=G^u*Z!DdcVLpC;Ymszud+Xq5g1rOv7ztHr=;Nu=Ur+)=v;z|-<ZckybX0ajuhhXz>T_+mOxwq8~p&7Y42`Yu;p`IEoswydc&q3)h-iMRGiU;<>5@XeGQK@ia9?}yZ(cdw(rlSMC9S~L+)G%f2LldK`<JC@JSNZb7Guu-E}HDho4V&rcWz=&$sHR-~tGccwaB+#p#r5Ks(yR;z{w%*|I(;nx$X4JHTacZBx{kYzQuz01VCx)cb?|xu3BsFwYb?V->w`b}3`;%_Qci#Ewyz)*E?UYOC-ti>BVGPO=bMtIq>Fd3OM-3Cp4l`iWr#@-i9m%Nay-vdpk(?%%6kJ^&L8_AD`Mx8IbOs!~>uj`+m#|MsF5irZ5una1)Q+VbBQ=U%&Pl#%>y-pTKlCu?##<~3qZeT@bjn>xeyk(GFRN1M#?dZQ>f3xIXZWifNU&<U2Npz~q#SXu)c?c<un-^;t>Zix0~;q~jwpL<!S6=ZT<&fO@dyAktiE$<Pa}vHU@jI6Oc#0{LR=oR%)v?%9K%2?lLnL-tp9N1T)?89C1&fcL!`sd{N7Uw-|XI03d9AMPvfp%tE$mL7IgW{BMw2<y)4*C*aa}MP_n`ud0>du>WXSl-qWpwO14nGw9s5iGYfurf13he9iQ>S;u{*qO=!p^#M*NiR;{x(zTAS?873`I)_V6oXKfL9WyQ_Krl|!29UBX6*sTJ+Hi)6-{}UCEg%_=)ka1rPUA<k0#BaaWE9eK-%7U}JpcccPHaq6XvFBrmhVvC|N}?)$za1(<Nvv<cqw!xGYfSG&SxIVaT1?wTfmJ$BNBg#cf5m$vLeCM{^7VVL)|J80#{+OJbq^Zapmb-eHfk<lycg%ZCF3b6V6hbUQb)7$dD$>@`?&Pa(4VL{zpDWnh#jwx00000c@Z&}J|v*N00EB~!$JT6WuK*1vBYQl0ssI200dcD"
BOOT_POLICY = "{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;E8JzE?odUh=?bAf%Oh?#lHU1qV{}3knS`3#W6;beh+3x(kNx(xS{R)?O<Pkrcxf}VO75o&L;73X6-?d-S+XHM-{?%*2jTjnGgX7&m=p*6^ocB+~xSQO~qqCLoPLXBgnMfDNaP7jJ*ws$UbgM4Y(4LhY5n(7mQ{r$x_2Ow}XOF>=1<`Nz3~NC!X60vboyzD^lw#4{7YKZ~oDNZ|hZvG~;qY3XdGrh~c3=I~LDuD@W_bKdd#!csrO^<AtqpCU##RV1$DzVOoOak-pTbz{`L}S8-1&O%OyIXyZGMv5|x_W$^#LFn}3sVdQkG&uj<e<lHPu=9f{xM@Mcn$8z?sUu?~TLAe5t-@h!s>Rv0nz{o;KA&-F?W{Rpsi6tI0vCpfSPgFJIKols_&dI}qy#s*sN!}8;h@I{<d8RZET7{vA$UE1P!hPWOZ&7|f|2l%>G&G>Z^52G`6$jHpMm~$`d*P@_72o;{shZSau+$njb!F70YqjTc<&jOr&8d=499;?7cUw$2PWR&)+F2KiA$di?q(v`hF$R$vZ^Om%^dB-($;Y=nm79os3hj)sOKQZTK$q5}nfvwF!^DgujljhQ#I2Z_t$`jJ;w<}rqa)d=95iA~n|mKury6z#wJXVM-!aHb1aL=e%SG!yGSyh6Pg+ZmEeZC52v$T`O=P+8#%-UdIuAb{ZJbhto_!CJoJ(Lu@z08c1oJdU3I4(co3qYK0v9|S*)fA3g8LXcKfKhMrdIbs1X4}wQ!^gK{CI!U!g+V*AB*%^AjjM5`%=YeZh2vd8KoE*nh1~{QN92Lxw;9)uJh1o*b6O|I9Q)(k{xGx-gye5oq&~kOBRo6m9ZsF+G?;-)AM3~vM}E&_T&h*i)LHHFTBuSq9Ppva6lCn(+?7m9(;~7L7iVcd$*HH|43W!Pn6kNXr@0g?X9&0syNjgH`;HLwocyQVVIZvo{^;r!4sbk9m&O;kc@SYrn$_$av8JeFws?wG~Sc#$W1GfiNSY6L}14)iqvt@u`b<!aAf3m0T$1*p3HIB;<v5hE$Oa@ep^C8{LV0OJ+?&a*I2m(q^d$=rYxPek=JiKM&(*=PORrl*IS$shQN=#n3e%9sd2XsCm16oNCmG0&K3I_Bg6g1ScNR*Zzf?^QM1qESE-eB&SzBF4=f~7_stCn1B3>vc;Zjd#lpQ1^L&H!E0{!>wO5wprJ{w<yU4`~?aN`$3U<dCt~Bi&cjRC_?Pt4oYr&$)97BF59!?D-(u9?SGmG;HC8G}+K5FY4Kcmc?(yqpqO>HTtX4G*dJR6Y22SY`aTHK|s8uaGV!f(tkiFGn`C{wBb)a0!IN=q}+BI_vFA0^CWl`1(NE7kBcI*p&oyvOErp>tU6!UV7jb><~erPx;Cg>CiqR2tZzdXMr%<D{PvhPlH~+!Wg^kZblD$7VwFvVejXcaB0VSA4Pmrhvr*4gGw$wEl8Be7g?iKzA|852<I`-&SX7Tk2}Xo`=8s?e)UUSO{w{G+Z`^4kEB&vbDI_u^tSpMG|s$iDqgEP_@VBIw*qL+1CbT@DWo{XW1rkfuBR05Iv1bCewh6NCo7f-KIgsaj17foE!{ealQqd5Fck2(vhXLDezU|WhPN~AmywrzK~Ob1T5$wnLK91B8#ao&PL_t9&E!D&kycD++jY#{nPe5rf+H5R})}Y69#Qm9P_OCsF#kJ48&k=RygvV;bzgkN9Z6qKliVRIUE_2I?9%+>^?jJfjD|i2zuCkFFlXHV7|Or>Ij(jcPkpLIa$2&UmYso)1iwqBF$tOS9QPnrnznO%-`_rsQT)`UWxNnu!LAqoD^o+^-t;cS#_HuzRDP8ZCL%?`IDKi=lkPlGHOc3Fo3xzXkU?`Y~7GcU_8JVHz|@g*CTVZ+#Exxgvn$%8@3i7lR(8x;~NJc${v|Lf?{%F*87w;oiUp{LwFnr*%Mb>)vLX-RK?p6qR_d)w*RERv#pweiHyQd1F+gHiy-)bW|-xHwJ!7G-}qcp0Gy1{OTmL$YbkhNf6x~rl~%mFsokwfyzK_B?_pGMveZg7Y#x!!Hc-^2Z5T>fIqi(@_JVB@X`I*8V}V$1U*EQ;xBvL$tvZF(5bgJhoo=O}^tKAGOeUttj$D;H<&0aOs3hyYyq0lz#gf_k_8-py0F8T-pX#4?kIHCNlcUMs)OdNn+m_t6?MfcaY=h(x*{pqbkzwsIL~n4!+CK;2-^erc)9>kGN;Mq-*ECZX&S;K|Rk5W8-7y_NHR&!59bBJ}pwRdKcaAY3P<;U@jj0KW4<U8)Q@8S(m_qeCoezR0;bZ999L{a#17E84{^<?GoXhAfG>K!cx|-ShBPwU*FzPw&#MzXLVzBxG8UV&AOUTxK?<9hi3A0MXIJ+69=mDcRp!5Hqzq6Y!`7&FI9et!|HOXn%)Exy@aVT5g5JhSDTztYH+D0QQKRRkQt6WUJJH4T|99qPAn-PzN31%8wGVcJE+>C$wybH$F`UxL1XvZyxZr`z!P*%(w9Ei7N6zA>@2cg+^#Q<!XNqfWoMEksciaiRW0lAE@mkQs}iVMO!h{jsGT$#raOgHCJ$LOqTV0?UYorH;Z%;}a%Z-p%vaeO;9yB(<rCSwYc08^2y-dwcnPN`id7+M<L%;w<kfNmnAoOsQ|ySA5=Hpt)_#wY9l?11Nc-_d7U0o>jt&1d65p`*b^{wKitYHz+u+adH(L-WVhCqZoM;VQ0vEW4oQ(8$tn-&K|-96CJSJN|GgtNj6D$9j1}VG=e3jirTS3rayMw`4LZN6Bcbb`4+VU#JRu>K4$HV*>)}^gGo|Tk~&#=zA5to!;7reaRp8MPf1DTSfm)w$hDU@BbhiDQ@$lK|FL>=t1^-q_eKO8Zzd+fYJ6)9<?IDGg5aV)8wuLoVnYhy(I@#t^@j5<~BkO1?#d23{6jbhdIs(44um-oNH~~&CgP-Ue6!T4d$<%`z1dl>+PW%5+eS>P(;w3Ai~FAF|&m?Y0#g<XtsWR=Zq}I|Lftc0p}a5Ft=wl;9YmE>2qx&A&$zo!OG7c9Ld=l!neVCrfZ`59bj+x3&3afN?B`LBnurjf*)4>6o@%HSCsV13D`cYmpwN><xhw3n^lGIIp;<kt;v?Qe2vjHU*3q%bujte8!l9n<o=?f5Oa|=AYiMHc#Qs{471H**jB`~5i&-B&372N7Fy@<o9s0o$;oSjGKxe0hRSUr@|jYjqz*gt1)n6tr?aK-N1em%(Xm4b`+UF-8?6|u8QTQQg4h-12?}`Qcjmz!U-Lm?{EIVgarif*3Ysr;tl@n6R2D|0M7P>Dtl@ey0Rx!Yt2~0%mCe6$@B9AFHr&&G<ZeU6<=}Sm)7#?o1H&9;9gpHB!PnJ~buXXY8<8=%30+~PSH-K#)Tg5dD^}ih5`duKJ!p%c1ED?xfM2WYa|)8;?G;k{e=3MWw@K-7{spqT@zb1ASy?JlBh!FKDv^y+a12P1bFHQ9W9f;a>qe9`-+esy!S6i=L>wxv6<Ee|6>asVH6-z9#UiX*o~iVI>>+El8c?NG24>R*P<X#Fj;QuFxbbyPi-X|s?-Ig$^%<y6m!%N&8nb|{l_nr5_6N!qag$vROYujVl_DRgvR8g){KS<a<~%q#l6N6DLSS~0Qo=p&(;p%6fch_*NopZ0WNv8+-@aC&M}UO$S}BwY)dZdLJ#{Cy*|vFjg0YLD+SjZ%Num01!b>PL%&9#huZ%*J`WQ!%<ULgtsBl^`0B}6gdClr#<^c6%stcW|p8=j|M{pB)6)RtylUJT+AJx(A?M^5tHtW{vd8pTe_MOp#%0W#HazNo>dWG@b?(Tp?7#DAGqi0#_8Mz+NZ`K#`x7#ZfSe+vG8nvUYLzu3KFYk!*?@{+pVBebQhY)2`z}3<yAUZ#X#ONY#Mi<?QRqROYLlfl>8AI`%1*A+C(|N9d=lHtMmR=l+?+=hHzqjX|X*<B$+Mx0Wqg2#OG%bw4-WfO?*Rz4rM;qT#n;B$@x_FYhlc~)VS(*+2iy=aCjt@I93NhBL>)z0m@AEB~*)a3vN4F9atjGWoEIyjf-`2;aT}9K(g%vMm*5F5jk9;Fb;f$0H2dN67jnvE}MIvWYw_y8}x92(4eiy`<okaA_-M|K`2KJ*nIu!mll-{F@g1<=YUA#NYH}%9S2nMFLr-F3`8Y1wTv<}f0A$#%RJe`4NIMPCJSZBrweA{tzuQqt7wanH0o#bX4P;Mj)BQ>UF0+@NKwWBc5wn`AKeFRi{bDnz9-Tx8Whk>mz#w8pVvRr<$CNnMnh}F5di-U7PFl3rgum|jw%DKC}YU$E)p4N^C*_)donI|sQ!nCoIX&`4Re;j&|QO8ElFD_7U+lmuJ0FWl8v2QCd7&;)BQ1cz23g@GCA2*AR0|k9lJdNp)E0v>a2Z@N=OF(Is%y*h8KgkUsMNSOzv_PLOA?mlcm3=mv1#e($KErM(+O=*~8PRfjX8fbvu<Cn`)?LbXq4r~~v;7we$N=B;e+gJvrVW5bPFXOZ*5jdlY?Jvrr2kWZ8O{r`WXVP2h1g1T8s!SvIh?}2)TL*AO2gaTddGNQ{fHzrb+Feg5nIvlGev0xE}Q%jkT(?o-Keo}rtuH*cfpU^+$g&TtTElzz?ezv#9U#TNWbZ?@QRd2#rp@Yj{bsIA4Vi@&5$QBZD>wmI_T*$?4<N8l~N~(@r-&UZ}iZSxmJ=N2TEtg%!xC+tvTuH(*-B4+=P*q66JbsO?I#%Z(*L-XY1D3T+kJs*+OzoZj_VngSxb}m&o3hd@FxG-{Vs1H3IMTez?<8dzp8uz-FBU20t64s!XdytukBSKUXGBb0E#84ZRL%?Mi9R3!QGN9OnEgvZ!czjgQ>|k%(8a7`Np1`XX$Iv;N1bn__&3t?=3UB~*@i;kLJs!w^sm*9brXdr*qj`5T#})Ja<^`Q^{g1k7u1v+<lvz>BKg4L*(~z<>|Q5@W*1{<Oq*6dXGb$Kbk6+UjT%*oB&$#8tODG$i2VYab4*>_A6;R}eO4_VZ488Q+X<bAT?1*}46mBe6hzuz|lkdSZyz#FH*yU7Q~2j~|4Vx5edhZ!1l^>WjEA#0r+f2aQK_J;O%AE^q7eUj)ixT58a91KzLw4iubwt3Apr2xzfsuI0o5M3xSG$t`(JRe{|JK}GOX_*SZ*u$Fa@UR+aa+327kz?!T#lRi4#2;t;s!m@9^Gpzxgu<&I96R8_pG{QOR=&}ktY13aw5(Avmp(daDloaoJdXs@nRf|cL7m!YgIc}sbcd#t#SWBm|L@RZjMHZL=k)$^uqFKBD?T#)=IAXW8q05tsG~nyGR*hAU@FLgASAsmGU;Hy$!!69vfiz^4qKs8TdESeeyAHCPPPR(cyB12aa8bih8<)%l>HLnwc%r;{I`9Y3Lrbm9F>NkP={_y|_s%DbTV=(BU$S1h3JDD#KQ$+k|JQGU3C5W_nX*liZ)n?orzvj85;Bmp7eu))zt;<zJoP&lZj-bwQ~a7e=-k*oaN-`#^hr=#qDIVNl^PPtJ5fjJ6A`O7Z4hJ%V?$bGZ3;2vgSkIAorNyo3hkS!l;${lUG|(<HUp!)#8;yUWz6eYSl^MJZa1HeBuLhqzEVu-qh^u(p8oq;X5;CJE+$Ibo9<0N)9g7GTG6VHw2Q*C4w1z28;r1;zmdUq!U7vDt}%1sQ#>!QjyUooY(XoZ7>ve7^d6#Inbx2(zGEZCOThf7=AKP;Xnn-^0pu4Qxf8)v2b>1q6bm#Tau<0p*9X~KmM+ldBVom_fuFCc0>Fg-!C`>8Wk$>0w#b8pu?O-;WQ%I4Xtoq@#T79MmCtzIuY8BgV%o2kGkJ~|I{`!GNh@MG3%*Qxotc6OfWWUtkh{VX(F%c$+K!5I&XH-6_cEL46zD@gb@_%A9Yw%I%LcEKXRJetGEG!XSIBAViVu~1eQGPdw-i1O?HwVi_f#1uBChq^78Y4_+S-x}U0dn^00000xgFNZ@^CEM00GJ*?2-ZiSCDTPvBYQl0ssI200dcD"
SLOTS = {
    "supply-initial-server": ("server-input", ("server-token", "agent-token"), (4096, 4096)),
    "read-server-join": ("server-input", (), ()),
    "supply-server-join": ("server-input", ("server-token", "agent-token"), (4096, 4096)),
    "read-agent-join": ("agent-input", (), ()),
    "supply-agent-join": ("agent-input", ("agent-token",), (4096,)),
    "check-admin": ("admin-access", (), ()),
    "supply-issuer-ca": ("issuer", ("tls.crt", "tls.key"), (262144, 262144)),
    "supply-issuer-acme": ("issuer", ("private-key",), (262144,)),
    "supply-registry-signing": ("registry-auth", ("signing-key",), (262144,)),
    "supply-registry-principal": ("registry-auth", ("password",), (262144,)),
    "supply-node-registry": ("node-registry", ("password",), (262144,)),
    "supply-recovery-key": ("recovery", ("identity",), (262144,)),
    "supply-recovery-server-token": ("recovery", ("server-token",), (4096,)),
}
PUBLIC = {"project", "environment", "target", "owner", "operation", "attempt", "source", "destination", "cluster",
          "resource", "issuer", "service", "principal", "origin", "recovery", "profile_sha256", "script_sha256"}
FIELDS = PUBLIC | {"protocol", "version", "action", "for_action", "request_id", "selection_sha256", "remaining_ms", "slot_lengths"}


class Refused(Exception):
    def __init__(self, code):
        self.code = code


def require(condition, code=2):
    if not condition:
        raise Refused(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 4)
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def identity(fd):
    value = os.fstat(fd)
    return [value.st_dev, value.st_ino]


def directory(path):
    require(path.startswith("/") and "\0" not in path)
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    protected = False
    for part in Path(path).parts[1:]:
        require(part not in (".", ".."))
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=current)
        os.close(current)
        current = fd
        value = os.fstat(fd)
        require(value.st_uid == 0 and not value.st_mode & 0o022)
        protected |= not value.st_mode & 0o077
    return current, protected


def read_file(path, maximum=MAXIMUM, private=True):
    parent, protected = directory(str(Path(path).parent))
    fd = os.open(Path(path).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
    try:
        value = os.fstat(fd)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1)
        require(not value.st_mode & 0o022 and value.st_size <= maximum)
        require(not private or not value.st_mode & 0o077 or protected)
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        require(len(result) == value.st_size and len(result) <= maximum)
        return bytes(result)
    finally:
        os.close(fd)
        os.close(parent)


def tool(profile):
    parent, _ = directory(str(Path(K3S).parent))
    fd = os.open(Path(K3S).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
    os.close(parent)
    value = os.fstat(fd)
    require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o022)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        digest.update(chunk)
    require(digest.hexdigest() == profile["k3s_sha256"])
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def command(fd, args, input=None, allowed=(0,), extra_fds=()):
    global WRITERS_SETTLED
    require(time.monotonic() < DEADLINE, 6)
    process = subprocess.Popen([f"/proc/self/fd/{fd}", *args], pass_fds=(fd, *extra_fds),
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/var/empty", "LANG": "C.UTF-8"})
    poll = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        poll.register(stream, selectors.EVENT_READ)
    pending = memoryview(input) if input is not None else None
    if pending is not None:
        os.set_blocking(process.stdin.fileno(), False)
        poll.register(process.stdin, selectors.EVENT_WRITE)
    until = min(DEADLINE, time.monotonic() + 20)
    completed = False
    try:
        while poll.get_map():
            require(time.monotonic() < until, 6)
            for event, _ in poll.select(min(0.05, max(0, until - time.monotonic()))):
                stream = event.fileobj
                if stream is process.stdin:
                    count = os.write(stream.fileno(), pending[:65536])
                    pending = pending[count:]
                    if not pending:
                        poll.unregister(stream)
                        stream.close()
                else:
                    chunk = os.read(stream.fileno(), 65536)
                    if chunk:
                        require(len(streams[stream]) + len(chunk) <= MAXIMUM, 4)
                        streams[stream].extend(chunk)
                    else:
                        poll.unregister(stream)
        process.wait(timeout=max(0.001, until - time.monotonic()))
        require(process.returncode in allowed, 5)
        completed = True
        return bytes(streams[process.stdout])
    finally:
        # A failed mutating API client can leave server-side work unresolved.
        # Killing the local process alone cannot justify a writer-ended receipt.
        if input is not None and not completed:
            WRITERS_SETTLED = False
        poll.close()
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                WRITERS_SETTLED = False
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def kubectl(fd, owner, *args, input=None):
    kubeconfig = f"{ROOT}/owners/{owner}/admin.yaml"
    read_file(kubeconfig, 65536)
    return command(fd, ["kubectl", "--kubeconfig", kubeconfig, "--request-timeout=10s", *args], input)


def opaque(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None


def schema(value, depth=0):
    require(depth <= 4, 4)
    if isinstance(value, str):
        require("\0" not in value, 4)
    elif isinstance(value, list):
        for item in value:
            schema(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            require(isinstance(key, str), 4)
            schema(key, depth + 1)
            schema(item, depth + 1)
    else:
        require(value is None or type(value) is int, 4)


def read_exact(length):
    result = bytearray()
    while len(result) < length:
        chunk = sys.stdin.buffer.read(length - len(result))
        require(chunk, 4)
        result.extend(chunk)
    return bytes(result)


def request():
    global DEADLINE
    length = struct.unpack(">I", read_exact(4))[0]
    require(0 < length <= 65536, 4)
    raw = read_exact(length)
    header = decode(raw)
    if isinstance(header, dict) and header.get("protocol") == "broil-k3s-state":
        state_main(raw, header)
        os._exit(0)
    if isinstance(header, dict) and header.get("protocol") == "broil-k3s-bootstrap":
        boot_main(raw, header)
        os._exit(0)
    require(length <= 4096, 4)
    schema(header)
    require(isinstance(header, dict) and set(header) == FIELDS and canonical(header) == raw, 4)
    require(header["protocol"] == "broil-k3s-actions" and header["version"] == 1, 4)
    require(re.fullmatch(r"[0-9a-f]{32}", header["request_id"]) is not None, 4)
    inspect = header["action"] == "inspect"
    action = header["for_action"] if inspect else header["action"]
    require(action in SLOTS and (inspect or header["for_action"] is None), 4)
    require(type(header["remaining_ms"]) is int and 0 < header["remaining_ms"] <= 7200000, 4)
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    for name in ("owner", "operation", "attempt"):
        require(opaque(header[name]))
    resource = header["resource"]
    require(isinstance(resource, dict) and set(resource) == {"kind", "id", "generation", "uid"})
    require(resource["kind"] == SLOTS[action][0] and opaque(resource["id"]) and opaque(resource["generation"]))
    for member in (header["source"], header["destination"]):
        if member is not None:
            require(isinstance(member, dict) and set(member) == {"machine", "member", "role", "node_uid"})
            require(member["role"] in ("server", "agent", "backup") and (member["node_uid"] is None or opaque(member["node_uid"])))
    if header["cluster"] is not None:
        require(set(header["cluster"]) == {"uid", "ca_sha256"} and opaque(header["cluster"]["uid"]))
        require(re.fullmatch("[0-9a-f]{64}", header["cluster"]["ca_sha256"]) is not None)
    lengths = header["slot_lengths"]
    require(isinstance(lengths, list) and len(lengths) <= 8 and all(type(n) is int and 0 < n <= 262144 for n in lengths), 4)
    require(sum(lengths) + 4 * len(lengths) <= MAXIMUM, 4)
    require(not inspect or not lengths, 4)
    return raw, header, action, inspect


def admit(header, action):
    require(os.geteuid() == 0)
    machine = header["source"] if action.startswith("read-") else header["destination"]
    require(machine is not None and os.environ.get("BROIL_MACHINE") == machine["machine"])
    require(os.environ.get("BROIL_ENV") == header["environment"])
    ownership = decode(read_file(f"{ROOT}/owners/{header['owner']}/ownership.json", 16384))
    require(set(ownership) == {"schema", "owner", "scope", "machine", "cluster", "data"})
    require(ownership["schema"] == 1 and ownership["owner"] == header["owner"])
    require(ownership["scope"] == {key:header[key] for key in ("project", "environment", "target")})
    require(ownership["machine"] == machine and ownership["cluster"] == header["cluster"])
    if ownership["data"] is not None:
        installed, _ = directory(DATA)
        require(identity(installed) == ownership["data"])
        os.close(installed)
    else:
        pending_recipient = machine["node_uid"] is None and action in (
            "supply-server-join", "supply-agent-join", "supply-node-registry", "supply-recovery-key", "supply-recovery-server-token")
        require(header["cluster"] is None or machine["role"] == "backup" or pending_recipient)
    profile_bytes = read_file(PROFILE, 16384, private=False)
    profile = decode(profile_bytes)
    require(hashlib.sha256(profile_bytes).hexdigest() == header["profile_sha256"])
    require(profile["schema"] == 1 and profile["script_sha256"] == header["script_sha256"])
    # Staging already verified this open script body; this independently binds
    # the action profile to the actual source carried by the configured script.
    require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == header["script_sha256"])
    resource = header["resource"]
    path = f"{ROOT}/owners/{header['owner']}/resources/{resource['id']}/{resource['generation']}"
    generation, _ = directory(path)
    st = os.fstat(generation)
    require(stat.S_IMODE(st.st_mode) == 0o700)
    record = decode(read_file(path + "/binding.json"))
    require(set(record) == {"schema", "directory", "projection", "inactive", "registration_pending"})
    require(record["schema"] == 1 and record["directory"] == identity(generation) and record["inactive"] is True)
    # Creation provenance stays immutable; only the current execution IDs may
    # differ. Current writer/grant authority was checked before this admission.
    projection = dict(record["projection"])
    require(set(projection) == {"schema", "binding", "declaration", "scripts", "registries", "secrets", "references", "profile"})
    require(projection["schema"] == 1 and projection["profile"] == profile)
    creation = projection["binding"]
    require(set(creation) == PUBLIC and opaque(creation["operation"]) and opaque(creation["attempt"]))
    projection["binding"] = dict(creation, operation=header["operation"], attempt=header["attempt"])
    require(projection["binding"] == {key: header[key] for key in PUBLIC})
    require(hashlib.sha256(canonical(projection)).hexdigest() == header["selection_sha256"])
    require(projection["declaration"]["version"] == profile["k3s_version"])
    selection(header, action, projection)
    source, destination = header["source"], header["destination"]
    if "join" in action:
        require(source is not None and source["role"] == "server" and source["machine"] != destination["machine"])
        require(destination["role"] == ("server" if "server" in action else "agent"))
    else:
        require(source is None)
    if action == "supply-initial-server":
        require(header["cluster"] is None and destination["role"] == "server")
        require(projection["declaration"]["members"][0]["machine"] == destination["machine"])
    else:
        require(header["cluster"] is not None)
    if machine["role"] != "backup":
        require(record["registration_pending"] is (machine["node_uid"] is None))
    fd = tool(profile)
    recovering = action in ("supply-recovery-key", "supply-recovery-server-token")
    if header["cluster"] is not None and machine["role"] == "server" and ownership["data"] is not None and not recovering:
        config = decode(kubectl(fd, header["owner"], "config", "view", "--raw", "--minify", "-o", "json"))
        clusters = config.get("clusters", [])
        require(len(clusters) == 1 and not clusters[0]["cluster"].get("insecure-skip-tls-verify", False))
        require(set(clusters[0]["cluster"]) == {"server", "certificate-authority-data"})
        users = config.get("users", [])
        require(len(users) == 1 and set(users[0]["user"]) == {"client-certificate-data", "client-key-data"})
        require(clusters[0]["cluster"]["server"] == projection["declaration"]["api"]["endpoint"])
        certificate = base64.b64decode(clusters[0]["cluster"]["certificate-authority-data"], validate=True)
        require(hashlib.sha256(certificate).hexdigest() == header["cluster"]["ca_sha256"])
        uid = kubectl(fd, header["owner"], "get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}")
        require(uid == header["cluster"]["uid"].encode())
        if machine["node_uid"] is not None:
            uid = kubectl(fd, header["owner"], "get", "node", machine["member"], "-o", "jsonpath={.metadata.uid}")
            require(uid == machine["node_uid"].encode())
    if machine["role"] == "agent" and machine["node_uid"] is not None:
        kubeconfig = DATA + "/agent/kubelet.kubeconfig"
        read_file(kubeconfig, 65536)
        args = ["kubectl", "--kubeconfig", kubeconfig, "--request-timeout=10s"]
        config = decode(command(fd, [*args, "config", "view", "--raw", "--minify", "-o", "json"]))
        require(len(config["clusters"]) == 1 and len(config["users"]) == 1)
        cluster = config["clusters"][0]["cluster"]
        require(set(cluster) == {"server", "certificate-authority"} and cluster["server"] in ("https://127.0.0.1:6443", "https://127.0.0.1:6444"))
        require(cluster["certificate-authority"] == DATA + "/agent/server-ca.crt")
        require(config["users"][0]["user"] == {"client-certificate": DATA + "/agent/client-kubelet.crt", "client-key": DATA + "/agent/client-kubelet.key"})
        read_file(DATA + "/agent/client-kubelet.key", 65536)
        require(hashlib.sha256(read_file(cluster["certificate-authority"], 65536, private=False)).hexdigest() == header["cluster"]["ca_sha256"])
        uid = command(fd, [*args, "get", "node", machine["member"], "-o", "jsonpath={.metadata.uid}"])
        require(uid == machine["node_uid"].encode())
    return generation, record, fd


def selection(header, action, projection):
    declared = projection["declaration"]
    expected_references = []
    selectors = {name for name in ("issuer", "service", "principal", "origin", "recovery") if header[name] is not None}
    expected = set()
    if action.startswith("supply-issuer-"):
        expected = {"issuer"}
        issuer = declared["infrastructure"]["issuers"][header["issuer"]]
        require(issuer["kind"] == ("private-ca" if action == "supply-issuer-ca" else "acme-http01"))
        expected_references = [issuer["certificate"], issuer["key"]] if action == "supply-issuer-ca" else [issuer["account_key"]]
    elif action.startswith("supply-registry-"):
        registry = declared["registry"]
        expected = {"service", "origin"}
        require(header["service"] == registry["name"] and registry["authentication"]["profile"] == "docker-auth")
        require(header["origin"] == normalized_origin(projection["registries"][registry["endpoint"]]["declaration"]["endpoint"]))
        if action == "supply-registry-principal":
            expected.add("principal")
            principal = registry["authentication"]["principals"][header["principal"]]
            expected_references = [principal["password"]]
            require(principal["purpose"] in ("publication", "node-pull", "maintenance"))
            require(principal["repositories"] and principal["actions"])
            if principal["purpose"] == "node-pull":
                require(principal["actions"] == ["pull"])
        else:
            require(registry["authentication"].get("signing_key") is not None)
            expected_references = [registry["authentication"]["signing_key"]]
    elif action == "supply-node-registry":
        expected = {"origin"}
        candidates = [node for node in declared["node_registries"]
                      if normalized_origin(projection["registries"][node["registry"]]["declaration"]["endpoint"]) == header["origin"]]
        require(len(candidates) == 1)
        expected_references = [candidates[0]["password"]]
    elif action.startswith("supply-recovery-"):
        expected = {"recovery"}
        require(header["recovery"] == header["resource"]["id"])
        expected_references = [declared["backup"]["identity"] if action == "supply-recovery-key" else declared["credentials"]["server_token"]]
    elif action == "supply-initial-server":
        expected_references = [declared["credentials"]["server_token"], declared["credentials"]["agent_token"]]
        require(expected_references[0] != expected_references[1])
    require(projection["references"] == expected_references)
    require(selectors == expected)
    for member in (header["source"], header["destination"]):
        if member is None:
            continue
        if member["role"] == "backup":
            require(action.startswith("supply-recovery-") and member["member"] is None and member["node_uid"] is None)
            require(member["machine"] == declared["backup"]["machine"])
        else:
            candidates = [item for item in declared["members"] if item["machine"] == member["machine"]]
            require(len(candidates) == 1 and candidates[0]["name"] == member["member"] and candidates[0]["role"] == member["role"])
    if action == "supply-agent-join" or action == "read-agent-join":
        require(header["destination"]["role"] == "agent")
    elif action == "supply-node-registry":
        require(header["destination"]["role"] in ("server", "agent"))
    elif not action.startswith("supply-recovery-"):
        require(header["destination"]["role"] == "server")
    is_secret = header["resource"]["kind"] in ("issuer", "registry-auth")
    require(opaque(header["resource"]["uid"]) if is_secret else header["resource"]["uid"] is None)


def selected_slots(header, action, projection):
    names, limits = SLOTS[action][1:]
    if action == "supply-node-registry":
        node = next(n for n in projection["declaration"]["node_registries"]
                    if normalized_origin(projection["registries"][n["registry"]]["declaration"]["endpoint"]) == header["origin"])
        if projection["registries"][node["registry"]]["ca_path"] is not None:
            names, limits = ("password", "ca.crt"), (262144, 262144)
    return names, limits


def normalized_origin(endpoint):
    from urllib.parse import urlsplit
    parsed = urlsplit(endpoint)
    host = parsed.hostname
    if ":" in host:
        host = "[" + host + "]"
    return f"{parsed.scheme}://{host}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"


def secret_target(header):
    kind = header["resource"]["kind"]
    require(kind in ("issuer", "registry-auth"))
    namespace = "cert-manager" if kind == "issuer" else "broil-registry"
    resource = {key: header["resource"][key] for key in ("kind", "id", "generation")}
    name = "broil-input-" + hashlib.sha256(canonical([header["owner"], resource])).hexdigest()[:40]
    return namespace, name


def secret_metadata(fd, header):
    namespace, name = secret_target(header)
    obj = decode(kubectl(fd, header["owner"], "get", "secret", name, "-n", namespace, "-o", "json"))
    metadata = obj["metadata"]
    require(metadata["uid"] == header["resource"]["uid"])
    require(metadata["labels"]["broil.dev/owner"] == header["owner"] and metadata["labels"]["broil.dev/generation"] == header["resource"]["generation"])
    require(metadata["labels"]["broil.dev/activation"] == "inactive")
    require(isinstance(obj.get("data", {}), dict))
    # Runtime qualification separately observes actual encrypted etcd values.
    # Every use also requires the pinned tool's current encryption status.
    status = command(fd, ["secrets-encrypt", "status"])
    require(b"Encryption Status: Enabled" in status)
    return obj


def token(path, server, ca):
    raw = read_file(path, 4097)
    if raw.endswith(b"\n"):
        raw = raw[:-1]  # Profile's one K3s file terminator; no controller trimming.
    role = b"server" if server else b"node"
    require(re.fullmatch(b"K10" + ca.encode() + b"::" + role + rb":[0-9a-f]{64}", raw) is not None, 3)
    return raw


def prerequisites(header, action, generation, record, fd):
    resource = header["resource"]
    path = f"{ROOT}/owners/{header['owner']}/resources/{resource['id']}/{resource['generation']}"
    current, _ = directory(path)
    require(identity(current) == identity(generation) == record["directory"])
    os.close(current)
    require(decode(read_file(path + "/binding.json")) == record)
    names, _ = selected_slots(header, action, record["projection"])
    if header["resource"]["kind"] in ("issuer", "registry-auth"):
        secret_metadata(fd, header)
    elif action.startswith("supply-"):
        require(header["resource"]["uid"] is None)
        require(not any(name in os.listdir(generation) for name in names))
    if action.startswith("read-"):
        # Only metadata admission here. Secret files are read in the private
        # sub-action after the controller has admitted destination staging.
        source, _ = directory(DATA + "/server")
        os.close(source)


def supply_files(generation, record, names, values):
    global EFFECTS
    require(identity(generation) == record["directory"])
    for name in names:
        require(name not in os.listdir(generation))
    for name, value in zip(names, values):
        EFFECTS = True
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=generation)
        try:
            offset = 0
            while offset < len(value):
                count = os.write(fd, value[offset:])
                require(count > 0, 5)
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
    os.fsync(generation)


def supply_secret(header, fd, names, values):
    global EFFECTS
    obj = secret_metadata(fd, header)
    namespace, name = secret_target(header)
    metadata = obj["metadata"]
    patches = [{"op": "test", "path": "/metadata/uid", "value": metadata["uid"]},
               {"op": "test", "path": "/metadata/resourceVersion", "value": metadata["resourceVersion"]},
               {"op": "test", "path": "/metadata/labels/broil.dev~1activation", "value": "inactive"}]
    if "data" not in obj:
        patches.append({"op": "add", "path": "/data", "value": {}})
    for key, value in zip(names, values):
        require(key not in obj.get("data", {}))
        patches.append({"op": "add", "path": "/data/" + key, "value": base64.b64encode(value).decode("ascii")})
    EFFECTS = True
    kubectl(fd, header["owner"], "patch", "secret", name, "-n", namespace, "--type=json", "--patch-file=/dev/stdin", "-o", "name", input=canonical(patches))


def validate_ca_pair(fd, values):
    handles = []
    try:
        for value in values:
            private = os.memfd_create("broil-k3s-issuer", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            handles.append(private)
            os.fchmod(private, 0o600)
            offset = 0
            while offset < len(value):
                count = os.write(private, value[offset:])
                require(count > 0, 5)
                offset += count
            os.lseek(private, 0, os.SEEK_SET)
            fcntl.fcntl(private, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        try:
            command(fd, ["kubectl", "create", "secret", "tls", "broil-validation", "--dry-run=client", "-o", "name",
                         f"--cert=/proc/self/fd/{handles[0]}", f"--key=/proc/self/fd/{handles[1]}"], extra_fds=tuple(handles))
        except Refused as error:
            raise Refused(3 if error.code == 5 else error.code)
    finally:
        for private in handles:
            os.close(private)


def apply(header, action, inspect, generation, record, fd):
    names, limits = selected_slots(header, action, record["projection"])
    expected = () if inspect else limits
    require(len(header["slot_lengths"]) == len(expected), 4)
    values = []
    for length, maximum in zip(header["slot_lengths"], expected):
        require(0 < length <= maximum and struct.unpack(">I", read_exact(4))[0] == length, 4)
        values.append(read_exact(length))
    require(sys.stdin.buffer.read(1) == b"", 4)
    prerequisites(header, action, generation, record, fd)
    if inspect or action == "check-admin":
        return 0, b""
    if action == "read-server-join":
        secure = token(DATA + "/server/token", True, header["cluster"]["ca_sha256"])
        agent = read_file(f"{ROOT}/owners/{header['owner']}/active/agent-token", 4096)
        require(re.fullmatch(rb"[0-9a-f]{64}", agent) is not None and agent != secure[-64:], 3)
        return 1, struct.pack(">I", len(secure)) + secure + struct.pack(">I", len(agent)) + agent
    if action == "read-agent-join":
        return 2, token(DATA + "/server/agent-token", False, header["cluster"]["ca_sha256"])
    if action == "supply-initial-server":
        require(values[0] != values[1] and all(re.fullmatch(rb"[0-9a-f]{64}", value) for value in values), 3)
    elif action in ("supply-server-join", "supply-agent-join"):
        role = b"server" if action == "supply-server-join" else b"node"
        require(re.fullmatch(b"K10" + header["cluster"]["ca_sha256"].encode() + b"::" + role + rb":[0-9a-f]{64}", values[0]) is not None, 3)
        if action == "supply-server-join":
            require(re.fullmatch(rb"[0-9a-f]{64}", values[1]) is not None, 3)
    elif action == "supply-recovery-server-token":
        expected = read_file(f"{ROOT}/owners/{header['owner']}/recovery/{header['recovery']}/server-token", 4096)
        require(values[0] == expected, 3)
    elif action == "supply-issuer-ca":
        validate_ca_pair(fd, values)
    if header["resource"]["kind"] in ("issuer", "registry-auth"):
        supply_secret(header, fd, names, values)
    else:
        supply_files(generation, record, names, values)
    return 0, b""


STATE_ACTIONS = {"inspect", "reserve-owner", "acquire-writer", "prepare-input",
                 "admit-credential", "seal-writer", "retire-writer", "rebind-claim", "prune-attempts"}
STATE_WORK = {"reserve-owner", "acquire-writer", "prepare-input", "admit-credential"}
STATE_KINDS = {
    "machine-claim": "scope owner member participants_sha256 generation active_attempt root_identity lock_identity",
    "reservation": "binding state members dispatches seal_sha256 retirement_sha256",
    "intent": "binding action payload_sha256 admitted_ms",
    "terminal": "binding action payload_sha256 outcome failure effect writer_ended resource resource_identity completed_ms",
    "seal": "binding dispatches terminal_sha256s sealed_ms",
    "retirement": "binding seals next_generation retired_ms",
    "credential-grant": "binding action admission_sha256 selection_sha256 resource",
    "host-history": "scope owner attempts_removed watermark_sequence chain_sha256",
}
STATE_FAILURES = {"configuration", "capability", "credential", "authentication", "trust", "ownership",
                  "integrity", "storage", "transport", "readiness", "timeout", "cancelled", "bound",
                  "unsupported-version", "busy"}


class StateRefused(Exception):
    def __init__(self, failure):
        self.failure = failure


def state_require(value, failure="integrity"):
    if not value:
        raise StateRefused(failure)


def state_check():
    state_require(time.monotonic() < DEADLINE, "timeout")


def state_fields(value, names):
    state_require(isinstance(value, dict) and set(value) == set(names.split()))


def state_hash(label, value):
    return hashlib.sha256(label.encode("ascii") + b"\n" + canonical(value)).hexdigest()


def state_hex(value, length=32):
    state_require(isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None)


def state_uint(value, minimum=0, maximum=18446744073709551615):
    state_require(type(value) is int and minimum <= value <= maximum, "bound")


def state_value(value, depth=0):
    state_require(depth <= 16, "bound")
    if isinstance(value, str):
        state_require("\0" not in value and len(value.encode("utf-8")) <= 4096, "bound")
    elif isinstance(value, (dict, list)):
        state_require(depth < 16 and len(value) <= 4096, "bound")
        if isinstance(value, dict):
            for key, item in value.items():
                state_require(isinstance(key, str))
                state_value(key, depth + 1)
                state_value(item, depth + 1)
        else:
            for item in value:
                state_value(item, depth + 1)
    elif type(value) is int:
        state_uint(value)
    else:
        state_require(value is None or type(value) is bool)


def state_scope(scope):
    state_fields(scope, "project environment target hash")
    state_require(isinstance(scope["project"], str) and scope["project"].startswith("/") and
                  str(Path(scope["project"])) == scope["project"] and ".." not in Path(scope["project"]).parts)
    state_require(isinstance(scope["environment"], str) and scope["environment"] and opaque(scope["target"]))
    state_require(scope["hash"] == state_hash("broil-infra-scope-v1", [scope[k] for k in ("project", "environment", "target")]))


def state_route(route):
    state_fields(route, "address port account host_key_sha256")
    state_require(isinstance(route["address"], str) and route["address"] and isinstance(route["account"], str) and route["account"])
    state_uint(route["port"], 1, 65535)
    state_hex(route["host_key_sha256"], 64)


def state_member(member):
    state_fields(member, "machine member role route jump node_uid")
    state_require(isinstance(member["machine"], str) and member["machine"] and member["role"] in ("server", "agent", "backup"))
    if member["role"] == "backup":
        state_require(member["member"] is None and member["node_uid"] is None)
    else:
        state_require(isinstance(member["member"], str) and member["member"] and (member["node_uid"] is None or opaque(member["node_uid"])))
    state_route(member["route"])
    if member["jump"] is not None:
        state_route(member["jump"])


def state_members(members, binding, excluded=None):
    """`excluded` null: `members` is the complete participant set."""
    state_require(isinstance(members, list) and 1 <= len(members) <= 128, "bound")
    for member in members:
        state_member(member)
    state_require(len({m["machine"] for m in members}) == len(members))
    if excluded is not None:
        return state_excluded(members, binding, excluded)
    state_require(binding["recipient"] in members and binding["participants_sha256"] == state_hash("broil-infra-participants-v1", [dict(m, node_uid=None) for m in members]))


def state_excluded(members, binding, excluded):
    """The unreachable-member exception: `members` with `excluded`'s member restored in its participant place
    hash to the binding's participants."""
    state_fields(excluded, "member reason")
    state_require(excluded["reason"] == "unreachable")
    state_member(excluded["member"])
    state_require(all(m["machine"] != excluded["member"]["machine"] for m in members) and binding["recipient"] in members)
    state_require(any(binding["participants_sha256"] == state_hash("broil-infra-participants-v1", [dict(m, node_uid=None) for m in
                      members[:i] + [excluded["member"]] + members[i:]]) for i in range(len(members) + 1)), "ownership")


def state_fingerprints(fingerprints):
    state_fields(fingerprints, "config_sha256 references_sha256 profile_sha256 script_sha256 tools")
    for name in ("config_sha256", "references_sha256", "profile_sha256", "script_sha256"):
        state_hex(fingerprints[name], 64)
    state_require(isinstance(fingerprints["tools"], list) and 1 <= len(fingerprints["tools"]) <= 128, "bound")
    previous = None
    for item in fingerprints["tools"]:
        state_fields(item, "name sha256")
        state_require(opaque(item["name"]) and (previous is None or previous.encode() < item["name"].encode()))
        state_hex(item["sha256"], 64)
        previous = item["name"]


def state_binding(binding):
    state_fields(binding, "scope owner operation attempt step dispatch recipient receiver_generation request_sha256 participants_sha256 fingerprints")
    state_scope(binding["scope"])
    for field in ("owner", "attempt", "dispatch"):
        state_hex(binding[field])
    state_require(isinstance(binding["operation"], str) and binding["operation"].startswith("infra-operation-"))
    state_hex(binding["operation"][16:])
    state_uint(binding["step"], 1, 4294967295)
    state_uint(binding["receiver_generation"])
    for field in ("request_sha256", "participants_sha256"):
        state_hex(binding[field], 64)
    state_member(binding["recipient"])
    state_fingerprints(binding["fingerprints"])


def state_resource(resource, binding, fresh=False):
    state_fields(resource, "kind id owner generation machine path namespace name uid")
    state_hex(resource["owner"])
    state_hex(resource["generation"])
    state_require(opaque(resource["id"]) and resource["owner"] == binding["owner"] and
                  resource["machine"] == binding["recipient"]["machine"], "ownership")
    kinds = {"server-input", "agent-input", "node-registry", "recovery"}
    state_require(resource["kind"] in kinds or (not fresh and resource["kind"] in ("admin-access", "issuer", "registry-auth")), "capability")
    path = f"{ROOT}/owners/{resource['owner']}/resources/{resource['id']}/{resource['generation']}"
    if resource["kind"] in ("issuer", "registry-auth"):
        partial = {k: resource[k] for k in ("kind", "id", "generation")}
        name = "broil-input-" + hashlib.sha256(canonical([resource["owner"], partial])).hexdigest()[:40]
        namespace = "cert-manager" if resource["kind"] == "issuer" else "broil-registry"
        state_require(resource["path"] is None and resource["namespace"] == namespace and resource["name"] == name and opaque(resource["uid"]), "ownership")
    else:
        state_require(resource["path"] == path and all(resource[k] is None for k in ("namespace", "name", "uid")), "ownership")
    return path


def state_application_secret(resource, binding):
    """The release lifecycle's `application-secret` Resource: no machine and no path, never
    prepared, its Secret's namespace and name and its admission-read UID or null for an absent Secret."""
    state_fields(resource, "kind id owner generation machine path namespace name uid")
    state_hex(resource["owner"])
    state_hex(resource["generation"])
    state_require(resource["kind"] == "application-secret" and resource["owner"] == binding["owner"] and
                  re.fullmatch(r"application-secret-[0-9a-f]{40}", str(resource["id"])) is not None and
                  resource["machine"] is None and resource["path"] is None and
                  re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", str(resource["namespace"])) is not None and
                  re.fullmatch(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?", str(resource["name"])) is not None and
                  (resource["uid"] is None or opaque(resource["uid"])), "ownership")


def state_cluster(cluster):
    if cluster is not None:
        state_fields(cluster, "uid ca_sha256")
        state_require(opaque(cluster["uid"]))
        state_hex(cluster["ca_sha256"], 64)


def state_private(fd, is_directory=False):
    value = os.fstat(fd)
    state_require(value.st_uid == 0 and stat.S_IMODE(value.st_mode) == (0o700 if is_directory else 0o600) and
                  (stat.S_ISDIR(value.st_mode) if is_directory else stat.S_ISREG(value.st_mode) and value.st_nlink == 1), "ownership")
    return value


def state_directory(path, create=False):
    state_check()
    parent, _ = directory(str(Path(path).parent))
    try:
        if create:
            try:
                os.mkdir(Path(path).name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
        try:
            state_private(fd, True)
            state_check()
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def state_names(path, maximum):
    fd = state_directory(path)
    try:
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                state_check()
                state_require(len(names) < maximum, "bound")
                names.append(entry.name)
        return sorted(names)
    finally:
        os.close(fd)


def state_read(path, kind=None):
    state_check()
    try:
        parent = state_directory(str(Path(path).parent))
    except FileNotFoundError:
        return None
    try:
        try:
            fd = os.open(Path(path).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            return None
        try:
            st = state_private(fd)
            state_require(st.st_size <= 65536, "bound")
            raw = os.read(fd, 65537)
            state_require(len(raw) == st.st_size and not os.read(fd, 1))
            record = decode(raw)
            state_value(record)
            state_require(raw == canonical(record) + b"\n")
            state_require(record.get("schema") == 1, "unsupported-version" if type(record.get("schema")) is int and record["schema"] > 1 else "integrity")
            if kind in STATE_KINDS:
                state_fields(record, "schema kind " + STATE_KINDS[kind])
                state_require(record["kind"] == kind)
                if "binding" in record:
                    state_binding(record["binding"])
            state_check()
            return record
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def state_publish(path, record, expected=None):
    global EFFECTS
    state_value(record)
    raw = canonical(record) + b"\n"
    state_require(len(raw) <= 65536, "bound")
    parent = state_directory(str(Path(path).parent))
    temporary = ".tmp-" + secrets.token_hex(16)
    fd = None
    try:
        state_check()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=parent)
        state_private(fd)
        EFFECTS = True
        offset = 0
        while offset < len(raw):
            state_check()
            count = os.write(fd, raw[offset:])
            state_require(count > 0, "storage")
            offset += count
        os.fsync(fd)
        state_check()
        name = Path(path).name
        if expected is None:
            # link is atomic no-replace publication; until the temporary name is
            # removed a crash leaves multi-link residue, which readers refuse.
            os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(temporary, dir_fd=parent)
        else:
            old = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
            try:
                state_private(old)
                state_require(identity(old) == expected, "ownership")
            finally:
                os.close(old)
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        state_check()
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def state_file_identity(path):
    parent = state_directory(str(Path(path).parent))
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
        try:
            state_private(fd)
            return identity(fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def state_mkdir(path):
    fd = state_directory(path, True)
    os.close(fd)


def state_purge(parent, name):
    """Remove `name` below the directory descriptor `parent` without following links."""
    state_check()
    if not stat.S_ISDIR(os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode):
        os.unlink(name, dir_fd=parent)
        return
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
    try:
        for entry in os.listdir(fd):
            state_purge(fd, entry)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent)


def state_now():
    return time.time_ns() // 1000000


class StateReceiver:
    def __init__(self, header):
        self.header = header
        self.binding = header["binding"]
        self.action = header["action"]
        self.payload = header["payload"]
        self.root = self.lock = None
        self.root_id = self.lock_id = None
        self.claim = self.reservation = None
        self.intent = None
        self.effect_started = False

    def profile(self):
        state_require(os.geteuid() == 0, "ownership")
        b = self.binding
        state_require(os.environ.get("BROIL_MACHINE") == b["recipient"]["machine"] and os.environ.get("BROIL_ENV") == b["scope"]["environment"], "ownership")
        raw = read_file(PROFILE, 16384, private=False)
        profile = decode(raw)
        state_require(hashlib.sha256(raw).hexdigest() == b["fingerprints"]["profile_sha256"] and
                      profile["script_sha256"] == b["fingerprints"]["script_sha256"] and
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == profile["script_sha256"], "ownership")
        tools = b["fingerprints"]["tools"]
        stable = [{"name": "bootstrap-index", "sha256": boot_index_sha256()}, {"name": "k3s", "sha256": profile["k3s_sha256"]}]
        state_require(tools == stable or (len(tools) == 3 and [tools[0], tools[2]] == stable and tools[1].get("name") == "bootstrap-recipe"
                                          and isinstance(tools[1].get("sha256"), str) and re.fullmatch("[0-9a-f]{64}", tools[1]["sha256"]) is not None), "capability")
        fd = tool(profile)
        os.close(fd)
        return profile

    def open(self, create):
        if create:
            state_mkdir("/var/lib/broil")
        try:
            self.root = state_directory(ROOT, create)
        except FileNotFoundError:
            return False
        self.root_id = identity(self.root)
        flags = os.O_RDWR | NOFOLLOW
        try:
            if create:
                try:
                    self.lock = os.open("mutation.lock", flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self.root)
                    os.fsync(self.lock)
                    os.fsync(self.root)
                except FileExistsError:
                    self.lock = os.open("mutation.lock", flags, dir_fd=self.root)
            else:
                self.lock = os.open("mutation.lock", flags, dir_fd=self.root)
        except FileNotFoundError:
            state_require(set(state_names(ROOT, 8)) <= {"action-profile.json"}, "ownership")
            return False
        state_require(state_private(self.lock).st_size == 0)
        try:
            fcntl.flock(self.lock, (fcntl.LOCK_SH if self.action in ("inspect", "bootstrap:inspect-host", "bootstrap:inspect-generation") else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StateRefused("busy")
        self.lock_id = identity(self.lock)
        self.revalidate()
        self.claim = state_read(ROOT + "/machine-claim.json", "machine-claim")
        self.reservation = state_read(self.attempt_path() + "/reservation.json", "reservation")
        if self.claim is not None:
            state_scope(self.claim["scope"])
            state_member(self.claim["member"])
            c, b = self.claim, self.binding
            # After `rebind-claim` the active attempt keeps its acquisition-time binding.
            rebound = (c["active_attempt"] == b["attempt"] and self.reservation is not None and
                       self.reservation["binding"]["participants_sha256"] == b["participants_sha256"])
            state_require(c["scope"] == b["scope"] and c["owner"] == b["owner"] and (c["participants_sha256"] == b["participants_sha256"] or rebound) and
                          b["recipient"] in (c["member"], dict(c["member"], node_uid=None)) and
                          c["root_identity"] == self.root_id and c["lock_identity"] == self.lock_id, "ownership")
        return True

    def revalidate(self):
        state_check()
        fd = state_directory(ROOT)
        try:
            state_require(identity(fd) == self.root_id and state_file_identity(ROOT + "/mutation.lock") == self.lock_id and
                          identity(self.lock) == self.lock_id, "ownership")
        finally:
            os.close(fd)

    def attempt_path(self):
        return ROOT + "/attempts/" + self.binding["attempt"]

    def dispatch_path(self, dispatch=None):
        return ROOT + "/dispatches/" + (dispatch or self.binding["dispatch"])

    def replace(self, path, record):
        self.revalidate()
        expected = state_file_identity(path)
        state_publish(path, record, expected)

    def machine(self):
        return {k:self.binding["recipient"][k] for k in ("machine", "member", "role", "node_uid")}

    def owned(self):
        state_require(self.claim is not None, "ownership")
        path = f"{ROOT}/owners/{self.binding['owner']}/ownership.json"
        value = state_read(path)
        state_require(value is not None, "ownership")
        state_fields(value, "schema owner scope machine cluster data")
        m = self.machine()
        state_require(value["owner"] == self.binding["owner"] and value["scope"] == {k:self.binding["scope"][k] for k in ("project", "environment", "target")} and
                      (value["machine"] == m or m["node_uid"] is None and dict(value["machine"], node_uid=None) == m), "ownership")
        state_cluster(value["cluster"])
        if value["data"] is not None:
            fd, _ = directory(DATA)
            try:
                state_require(identity(fd) == value["data"], "ownership")
            finally:
                os.close(fd)
        return value

    def active(self):
        self.owned()
        state_require(state_read(self.attempt_path() + "/seal.json", "seal") is None and
                      state_read(self.attempt_path() + "/retirement.json", "retirement") is None, "ownership")
        state_require(self.reservation is not None and self.reservation["state"] in ("reserved", "active") and
                      self.claim["active_attempt"] == self.binding["attempt"] and
                      self.claim["generation"] == self.binding["receiver_generation"], "ownership")
        original = self.reservation["binding"]
        state_require(all(original[k] == self.binding[k] for k in original if k not in ("step", "dispatch")), "ownership")

    def ledger(self):
        path = ROOT + "/dispatches"
        try:
            names = state_names(path, 1048576)
        except FileNotFoundError:
            return []
        work = []
        total = 0
        for name in names:
            state_hex(name)
            directory_path = path + "/" + name
            entries = set(state_names(directory_path, 3)) - {"bootstrap-input.json"}
            state_require(entries in ({"intent.json"}, {"intent.json", "terminal.json"}))
            intent = state_read(directory_path + "/intent.json", "intent")
            state_require(intent is not None and intent["binding"]["dispatch"] == name)
            terminal = state_read(directory_path + "/terminal.json", "terminal")
            if terminal is not None:
                state_require(terminal["binding"] == intent["binding"] and terminal["action"] == intent["action"] and
                              terminal["payload_sha256"] == intent["payload_sha256"] and terminal["writer_ended"] is True)
            if intent["binding"]["attempt"] == self.binding["attempt"]:
                state_require(intent["binding"]["owner"] == self.binding["owner"] and intent["binding"]["scope"] == self.binding["scope"], "ownership")
                total += len(canonical(intent)) + 1 + (len(canonical(terminal)) + 1 if terminal else 0)
                state_require(total <= 33554432 and len(work) < 1024, "bound")
                work.append((name, intent, terminal))
            elif terminal is None:
                raise StateRefused("busy")
        return work

    def begin(self):
        path = self.dispatch_path()
        previous = state_read(path + "/intent.json", "intent")
        if previous is not None:
            state_require(previous["binding"] == self.binding and previous["action"] == self.action and
                          previous["payload_sha256"] == state_hash("broil-infra-step-v1", self.payload), "ownership")
            terminal = state_read(path + "/terminal.json", "terminal")
            state_require(terminal is not None, "busy")
            return terminal
        work = self.ledger()
        state_require(all(t is not None for _, _, t in work), "busy")
        if self.reservation is not None:
            actual = [name for name, intent, _ in work if intent["action"] in STATE_WORK or intent["action"].startswith(("credential:", "bootstrap:", "lifecycle:"))]
            state_require(set(actual) == set(self.reservation["dispatches"]) and len(actual) == len(self.reservation["dispatches"]), "ownership")
        state_require(len(work) < 1024, "bound")
        state_mkdir(ROOT + "/dispatches")
        parent = state_directory(ROOT + "/dispatches")
        try:
            os.mkdir(self.binding["dispatch"], 0o700, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        self.intent = {"schema":1, "kind":"intent", "binding":self.binding, "action":self.action,
                       "payload_sha256":state_hash("broil-infra-step-v1", self.payload), "admitted_ms":state_now()}
        self.revalidate()
        state_publish(path + "/intent.json", self.intent)
        if self.reservation is not None and (self.action in STATE_WORK or self.action.startswith(("credential:", "bootstrap:"))):
            self.reservation["dispatches"].append(self.binding["dispatch"])
            self.replace(self.attempt_path() + "/reservation.json", self.reservation)
        return None

    def terminal(self, outcome, failure, resource=None, resource_identity=None):
        state_require(self.intent is not None and WRITERS_SETTLED, "busy")
        value = {"schema":1, "kind":"terminal", "binding":self.binding, "action":self.action,
                 "payload_sha256":self.intent["payload_sha256"], "outcome":outcome, "failure":failure,
                 "effect":"complete" if outcome == "succeeded" else "unknown" if self.effect_started else "absent",
                 "writer_ended":True, "resource":resource, "resource_identity":resource_identity, "completed_ms":state_now()}
        self.revalidate()
        state_publish(self.dispatch_path() + "/terminal.json", value)
        return value

    def resource(self, resource):
        ownership = self.owned()
        path = state_resource(resource, self.binding)
        try:
            fd = state_directory(path)
        except FileNotFoundError:
            state_require(resource["kind"] in ("server-input", "agent-input", "node-registry", "recovery"), "capability")
            # Missing ancestors are observed without creating them. Existing
            # parents are checked by the no-follow walk, including mode/owner.
            return {"resource":resource, "identity":None, "inactive":None}
        try:
            record = state_read(path + "/binding.json")
            state_fields(record, "schema directory projection inactive registration_pending")
            state_require(record["directory"] == identity(fd) and record["inactive"] is True, "ownership")
            binding = record["projection"]["binding"]
            state_require(binding["owner"] == resource["owner"] and binding["resource"] == {k:resource[k] for k in ("kind", "id", "generation", "uid")} and
                          binding["cluster"] in (ownership["cluster"], None) and all(binding[k] == self.binding["scope"][k] for k in ("project", "environment", "target")), "ownership")
            state_require(binding["destination"]["machine"] == resource["machine"] or
                          binding["source"] is not None and binding["source"]["machine"] == resource["machine"], "ownership")
            if resource["kind"] in ("issuer", "registry-auth"):
                executable = tool(record["projection"]["profile"])
                try:
                    obj = secret_metadata(executable, binding)
                    return {"resource":resource, "identity":obj["metadata"]["uid"], "inactive":True}
                finally:
                    os.close(executable)
            return {"resource":resource, "identity":identity(fd), "inactive":True}
        finally:
            os.close(fd)

    def inspect(self, data):
        payload = self.payload
        subject = payload["subject"]
        if subject in ("owner", "writer"):
            state_require(all(t is not None or i["action"].startswith("lifecycle:") for _, i, t in self.ledger()), "busy")
        if subject == "owner":
            data["claim"] = self.claim
            if self.claim is not None:
                data["ownership"] = self.owned()
            else:
                state_require(self.reservation is None, "ownership")
                self.no_installation()
            return "ok" if self.claim is not None else "absent"
        if subject == "writer":
            self.owned()
            data["claim"], data["reservation"] = self.claim, self.reservation
            if self.reservation is not None:
                data["seal"] = state_read(self.attempt_path() + "/seal.json", "seal")
                data["retirement"] = state_read(self.attempt_path() + "/retirement.json", "retirement")
            return "ok" if self.reservation is not None else "absent"
        if subject == "dispatch":
            path = self.dispatch_path(payload["dispatch"])
            intent = state_read(path + "/intent.json", "intent")
            if intent is None:
                return "absent"
            state_require(intent["binding"]["scope"] == self.binding["scope"] and intent["binding"]["owner"] == self.binding["owner"] and
                          intent["binding"]["operation"] == self.binding["operation"] and intent["binding"]["attempt"] == self.binding["attempt"], "ownership")
            data["terminal"] = state_read(path + "/terminal.json", "terminal")
            return "ok" if data["terminal"] is not None else "unknown"
        if subject == "resource":
            data["resource"] = self.resource(payload["resource"])
            return "absent" if data["resource"]["identity"] is None else "ok"
        ownership = self.owned()
        self.installed_identity(ownership)
        data["identity"] = {"member":self.binding["recipient"], "cluster":ownership["cluster"],
                            "readiness":{k:"unobserved" for k in ("api", "quorum", "nodes", "services", "storage", "publication")}}
        return "ok"

    def installed_identity(self, ownership):
        cluster, member = ownership["cluster"], self.binding["recipient"]
        if cluster is None:
            state_require(ownership["data"] is None and member["node_uid"] is None, "ownership")
            self.no_installation()
            return
        if ownership["data"] is None:
            # A genuinely unregistered recipient can belong to the installed
            # selection without inventing a node or local installation.
            state_require(member["node_uid"] is None, "ownership")
            self.no_installation()
            return
        state_require(member["node_uid"] is not None, "ownership")
        executable = tool(decode(read_file(PROFILE, 16384, private=False)))
        try:
            if member["role"] == "server":
                config = decode(kubectl(executable, self.binding["owner"], "config", "view", "--raw", "--minify", "-o", "json"))
                state_require(len(config.get("clusters", [])) == 1 and len(config.get("users", [])) == 1, "ownership")
                current = config["clusters"][0]["cluster"]
                state_require(set(current) == {"server", "certificate-authority-data"} and
                              set(config["users"][0]["user"]) == {"client-certificate-data", "client-key-data"}, "ownership")
                certificate = base64.b64decode(current["certificate-authority-data"], validate=True)
                state_require(hashlib.sha256(certificate).hexdigest() == cluster["ca_sha256"], "ownership")
                state_require(kubectl(executable, self.binding["owner"], "get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}") == cluster["uid"].encode(), "ownership")
                observed = kubectl(executable, self.binding["owner"], "get", "node", member["member"], "-o", "jsonpath={.metadata.uid}")
            elif member["role"] == "agent":
                path = DATA + "/agent/kubelet.kubeconfig"
                read_file(path, 65536)
                args = ["kubectl", "--kubeconfig", path, "--request-timeout=10s"]
                config = decode(command(executable, [*args, "config", "view", "--raw", "--minify", "-o", "json"]))
                state_require(len(config["clusters"]) == 1 and len(config["users"]) == 1, "ownership")
                current = config["clusters"][0]["cluster"]
                state_require(set(current) == {"server", "certificate-authority"} and current["server"] in ("https://127.0.0.1:6443", "https://127.0.0.1:6444") and
                              current["certificate-authority"] == DATA + "/agent/server-ca.crt" and
                              config["users"][0]["user"] == {"client-certificate":DATA + "/agent/client-kubelet.crt", "client-key":DATA + "/agent/client-kubelet.key"}, "ownership")
                read_file(DATA + "/agent/client-kubelet.key", 65536)
                state_require(hashlib.sha256(read_file(current["certificate-authority"], 65536, private=False)).hexdigest() == cluster["ca_sha256"], "ownership")
                observed = command(executable, [*args, "get", "node", member["member"], "-o", "jsonpath={.metadata.uid}"])
            else:
                raise StateRefused("capability")
            state_require(observed == member["node_uid"].encode(), "ownership")
        finally:
            os.close(executable)

    def no_installation(self):
        for path in (DATA, "/etc/rancher/k3s", "/etc/systemd/system/k3s.service", "/etc/systemd/system/k3s-agent.service"):
            try:
                os.lstat(path)
            except FileNotFoundError:
                continue
            raise StateRefused("ownership")

    def reserve(self, data):
        b = self.binding
        state_require(self.reservation is None, "ownership")
        if self.claim is not None:
            state_require(self.claim["generation"] == b["receiver_generation"] and self.claim["active_attempt"] is None, "ownership")
            state_require(self.owned()["cluster"] in (self.payload["cluster"], None), "ownership")
        else:
            state_require(b["receiver_generation"] == 0, "ownership")
            self.no_installation()
            # The new record carries the payload cluster: null for a creation, the owner's for a replacement
            # preparation's new machine.
            state_require(b["recipient"]["node_uid"] is None, "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
        else:
            if self.claim is None:
                self.effect_started = True
                state_mkdir(ROOT + "/owners")
                state_mkdir(f"{ROOT}/owners/{b['owner']}")
                ownership = {"schema":1, "owner":b["owner"], "scope":{k:b["scope"][k] for k in ("project", "environment", "target")},
                             "machine":self.machine(), "cluster":self.payload["cluster"], "data":None}
                state_publish(f"{ROOT}/owners/{b['owner']}/ownership.json", ownership)
                self.claim = {"schema":1, "kind":"machine-claim", "scope":b["scope"], "owner":b["owner"], "member":b["recipient"],
                              "participants_sha256":b["participants_sha256"], "generation":1, "active_attempt":None,
                              "root_identity":self.root_id, "lock_identity":self.lock_id}
                state_publish(ROOT + "/machine-claim.json", self.claim)
            data["terminal"] = self.terminal("succeeded", None)
        data["claim"], data["ownership"] = self.claim, self.owned()

    def acquire(self, data):
        b = self.binding
        self.owned()
        state_require(self.reservation is None and self.claim["active_attempt"] is None and self.claim["generation"] == b["receiver_generation"], "ownership")
        state_uint(self.claim["generation"], 1, 18446744073709551614)
        # The host's watermark and attempt cap with its recovery reserve.
        history = state_read(ROOT + "/history.json", "host-history")
        state_require(self.payload["sequence"] > (0 if history is None else history["watermark_sequence"]), "ownership")
        state_mkdir(ROOT + "/attempts")
        attempts = state_names(ROOT + "/attempts", 16384)
        state_require(len(attempts) < (16384 if self.payload["reserve"] else 16368), "bound")
        for attempt in attempts:
            state_hex(attempt)
            r = state_read(ROOT + "/attempts/" + attempt + "/reservation.json", "reservation")
            state_require(r is not None and r["state"] == "retired", "busy")
            retirement = state_read(ROOT + "/attempts/" + attempt + "/retirement.json", "retirement")
            state_require(retirement is not None and r["retirement_sha256"] == state_hash("broil-infra-retirement-v1", retirement) and
                          retirement["next_generation"] <= self.claim["generation"], "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        self.effect_started = True
        state_mkdir(self.attempt_path())
        generation = self.claim["generation"] + 1
        binding = dict(b, receiver_generation=generation)
        work = sorted(self.ledger(), key=lambda item:(item[1]["binding"]["step"], item[0]))
        self.reservation = {"schema":1, "kind":"reservation", "binding":binding, "state":"reserved", "members":self.payload["members"],
                            "dispatches":[name for name, intent, _ in work if intent["action"] in STATE_WORK], "seal_sha256":None, "retirement_sha256":None}
        state_publish(self.attempt_path() + "/reservation.json", self.reservation)
        self.claim.update(generation=generation, active_attempt=b["attempt"])
        self.replace(ROOT + "/machine-claim.json", self.claim)
        data["terminal"] = self.terminal("succeeded", None)
        data["claim"], data["reservation"] = self.claim, self.reservation

    def rebind(self, data):
        """Replace only the claim's participant binding under the active writer."""
        self.active()
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        self.effect_started = True
        self.claim["participants_sha256"] = self.payload["participants_sha256"]
        self.replace(ROOT + "/machine-claim.json", self.claim)
        data["terminal"] = self.terminal("succeeded", None)
        data["claim"] = self.claim

    def prune(self, data):
        """Remove retired attempts with the dispatch entries their reservations list,
        without a writer, and extend the host checkpoint."""
        global EFFECTS
        b, p = self.binding, self.payload
        self.owned()
        state_require(self.claim["generation"] == b["receiver_generation"] and b["operation"] == "infra-operation-" + b["attempt"] and
                      b["request_sha256"] == state_hash("broil-history-host-v1", {"prune":b["attempt"], "machine":b["recipient"]["machine"],
                                                                                    "attempts":p["attempts"]}), "ownership")
        history = state_read(ROOT + "/history.json", "host-history")
        state_require(history is None or history["scope"] == b["scope"] and history["owner"] == b["owner"], "ownership")
        present = []
        for attempt in p["attempts"]:
            try:
                os.close(state_directory(ROOT + "/attempts/" + attempt))
            except FileNotFoundError:
                continue
            r = state_read(ROOT + "/attempts/" + attempt + "/reservation.json", "reservation")
            state_require(r is not None and r["state"] == "retired" and r["binding"]["attempt"] == attempt and
                          r["binding"]["owner"] == b["owner"] and r["binding"]["scope"] == b["scope"], "ownership")
            for d in r["dispatches"]:
                state_hex(d)
            present.append((attempt, r["dispatches"]))
        removed = []
        if present:
            state_mkdir(ROOT + "/attempts-trash")
            trash = state_directory(ROOT + "/attempts-trash")
            try:
                for name in os.listdir(trash):
                    EFFECTS = True
                    state_purge(trash, name)
                for attempt, dispatches in present:
                    for base, name in [(ROOT + "/dispatches", d) for d in dispatches] + [(ROOT + "/attempts", attempt)]:
                        self.revalidate()
                        fd = state_directory(base)
                        try:
                            try:
                                os.lstat(name, dir_fd=fd)
                            except FileNotFoundError:
                                continue
                            EFFECTS = True
                            os.rename(name, name, src_dir_fd=fd, dst_dir_fd=trash)
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                    removed.append(attempt)
                os.fsync(trash)
                for name in os.listdir(trash):
                    state_purge(trash, name)
                os.fsync(trash)
            finally:
                os.close(trash)
        old = history or {"attempts_removed":0, "watermark_sequence":0, "chain_sha256":"0" * 64}
        record = {"schema":1, "kind":"host-history", "scope":b["scope"], "owner":b["owner"],
                  "attempts_removed":old["attempts_removed"] + len(removed),
                  "watermark_sequence":max(old["watermark_sequence"], p["watermark_sequence"]),
                  "chain_sha256":state_hash("broil-history-host-chain-v1", {"previous":old["chain_sha256"], "attempts":removed}) if removed else old["chain_sha256"]}
        if history is None:
            self.revalidate()
            state_publish(ROOT + "/history.json", record)
        elif record != history:
            self.replace(ROOT + "/history.json", record)
        try:
            remaining = len(state_names(ROOT + "/attempts", 16384))
        except FileNotFoundError:
            remaining = 0
        data["claim"], data["history"] = self.claim, {"attempts":remaining, "checkpoint":record}

    def prepare_input(self, data, profile):
        self.active()
        resource, projection = self.payload["resource"], self.payload["projection"]
        path = state_resource(resource, self.binding, True)
        state_fields(projection, "schema binding declaration scripts registries secrets references profile")
        state_require(projection["schema"] == 1 and projection["profile"] == profile)
        p = projection["binding"]
        state_require(set(p) == PUBLIC and p["owner"] == self.binding["owner"] and p["operation"] == self.binding["operation"] and
                      p["attempt"] == self.binding["attempt"] and all(p[k] == self.binding["scope"][k] for k in ("project", "environment", "target")) and
                      p["destination"] == self.machine() and
                      p["resource"] == {k:resource[k] for k in ("kind", "id", "generation", "uid")} and p["cluster"] == self.owned()["cluster"], "ownership")
        candidates = []
        for action, (kind, _, _) in SLOTS.items():
            if kind != resource["kind"] or not action.startswith("supply-"):
                continue
            try:
                selection(p, action, projection)
                if action == "supply-initial-server":
                    require(p["cluster"] is None and p["source"] is None)
                else:
                    require(p["cluster"] is not None)
                candidates.append(action)
            except (Refused, KeyError, TypeError):
                pass
        state_require(len(candidates) == 1, "capability")
        state_require(self.resource(resource)["identity"] is None, "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        # The exact approved destination is checked again while the unchanged
        # writer lock is held; exclusive mkdir prevents replacing a late arrival.
        state_require(self.resource(resource)["identity"] is None, "ownership")
        self.effect_started = True
        base = f"{ROOT}/owners/{resource['owner']}/resources"
        state_mkdir(base)
        state_mkdir(base + "/" + resource["id"])
        parent = state_directory(base + "/" + resource["id"])
        try:
            os.mkdir(resource["generation"], 0o700, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        fd = state_directory(path)
        try:
            ident = identity(fd)
            state_publish(path + "/binding.json", {"schema":1, "directory":ident, "projection":projection,
                                                   "inactive":True, "registration_pending":p["destination"]["node_uid"] is None})
        finally:
            os.close(fd)
        self.reservation["state"] = "active"
        self.replace(self.attempt_path() + "/reservation.json", self.reservation)
        data["terminal"] = self.terminal("succeeded", None, resource, ident)
        data["resource"] = {"resource":resource, "identity":ident, "inactive":True}

    def grant(self, data):
        self.active()
        p = self.payload
        # An `application-secret` Resource is never prepared: its grant names that one Secret.
        state_require(p["action"] == "apply-secret" or self.resource(p["resource"])["identity"] is not None,
                      "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        self.effect_started = True
        state_mkdir(self.attempt_path() + "/credentials")
        binding = dict(self.binding, step=p["credential_step"], dispatch=p["request_id"])
        state_publish(self.attempt_path() + "/credentials/" + p["request_id"] + ".json",
                      {"schema":1, "kind":"credential-grant", "binding":binding, "action":p["action"],
                       "admission_sha256":p["admission_sha256"], "selection_sha256":p["selection_sha256"], "resource":p["resource"]})
        data["terminal"] = self.terminal("succeeded", None, p["resource"])

    def seal(self, data):
        self.active()
        state_require(self.payload["members"] == self.reservation["members"], "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        ledger = {name:(intent, terminal) for name, intent, terminal in self.ledger()}
        work = self.reservation["dispatches"]
        state_require(all(ledger[n][1] is not None for n in work), "busy")
        self.effect_started = True
        seal = {"schema":1, "kind":"seal", "binding":self.binding, "dispatches":work,
                "terminal_sha256s":[state_hash("broil-infra-receipt-v1", ledger[n][1]) for n in work], "sealed_ms":state_now()}
        state_publish(self.attempt_path() + "/seal.json", seal)
        self.reservation.update(state="sealed", seal_sha256=state_hash("broil-infra-seal-v1", seal))
        self.replace(self.attempt_path() + "/reservation.json", self.reservation)
        data["terminal"] = self.terminal("succeeded", None)
        data["reservation"], data["seal"] = self.reservation, seal

    def retire(self, data):
        self.owned()
        b = self.binding
        state_require(self.reservation is not None and self.reservation["state"] == "sealed" and
                      self.claim["generation"] == b["receiver_generation"] and self.claim["active_attempt"] == b["attempt"], "ownership")
        seals = self.payload["seals"]
        # The seal map over `members`, or, with `excluded` null, exactly this host's own
        # entry (the replacement-preparation exception).
        machines = [s["machine"] for s in seals]
        state_require(self.payload["members"] == self.reservation["members"] and
                      (machines == [m["machine"] for m in self.reservation["members"]] or
                       self.payload["excluded"] is None and machines == [b["recipient"]["machine"]]), "ownership")
        own = next(s for s in seals if s["machine"] == b["recipient"]["machine"])
        seal = state_read(self.attempt_path() + "/seal.json", "seal")
        state_require(seal is not None and own["generation"] == b["receiver_generation"] and
                      own["seal_sha256"] == self.reservation["seal_sha256"] == state_hash("broil-infra-seal-v1", seal), "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        self.effect_started = True
        generation = self.claim["generation"] + 1
        state_uint(generation, 1)
        retirement = {"schema":1, "kind":"retirement", "binding":b, "seals":seals, "next_generation":generation, "retired_ms":state_now()}
        state_publish(self.attempt_path() + "/retirement.json", retirement)
        self.claim.update(generation=generation, active_attempt=None)
        self.replace(ROOT + "/machine-claim.json", self.claim)
        self.reservation.update(state="retired", retirement_sha256=state_hash("broil-infra-retirement-v1", retirement))
        self.replace(self.attempt_path() + "/reservation.json", self.reservation)
        data["terminal"] = self.terminal("succeeded", None)
        data["claim"], data["reservation"], data["retirement"] = self.claim, self.reservation, retirement


def state_request(raw, header):
    global DEADLINE
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms payload")
    state_require(header["protocol"] == "broil-k3s-state" and canonical(header) == raw)
    state_require(type(header["version"]) is int and header["version"] == 1,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
    state_require(header["action"] in STATE_ACTIONS, "capability")
    state_hex(header["request_id"])
    state_binding(header["binding"])
    state_uint(header["remaining_ms"], 1, 30000)
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    p, b = header["payload"], header["binding"]
    action = header["action"]
    fields = {"inspect":"subject dispatch resource", "reserve-owner":"members excluded cluster fingerprints",
              "acquire-writer":"members excluded sequence reserve", "prepare-input":"resource projection",
              "admit-credential":"action request_id credential_step admission_sha256 selection_sha256 resource",
              "seal-writer":"members excluded", "retire-writer":"seals members excluded", "rebind-claim":"members participants_sha256",
              "prune-attempts":"attempts watermark_sequence"}
    state_fields(p, fields[action])
    if action == "inspect":
        state_require(p["subject"] in ("owner", "writer", "dispatch", "resource", "identity"))
        if p["subject"] == "dispatch":
            state_hex(p["dispatch"])
        else:
            state_require(p["dispatch"] is None)
        if p["subject"] == "resource":
            state_resource(p["resource"], b)
        else:
            state_require(p["resource"] is None)
    elif action in ("reserve-owner", "acquire-writer", "seal-writer", "retire-writer"):
        state_members(p["members"], b, p["excluded"])
        if action == "reserve-owner":
            state_cluster(p["cluster"])
            state_require(p["fingerprints"] == b["fingerprints"])
        elif action == "acquire-writer":
            state_require(type(p["sequence"]) is int and 1 <= p["sequence"] < 2**64 and type(p["reserve"]) is bool)
    elif action == "prepare-input":
        state_resource(p["resource"], b, True)
    elif action == "admit-credential":
        state_require(p["action"] in SLOTS or p["action"] == "apply-secret")
        state_hex(p["request_id"])
        state_uint(p["credential_step"], 1, 4294967295)
        state_hex(p["admission_sha256"], 64)
        state_hex(p["selection_sha256"], 64)
        # The release Secret wire's slot admits exactly its own Resource kind.
        if p["action"] == "apply-secret" or isinstance(p["resource"], dict) and \
                p["resource"].get("kind") == "application-secret":
            state_require(p["action"] == "apply-secret", "capability")
            state_application_secret(p["resource"], b)
        else:
            state_resource(p["resource"], b)
    elif action == "rebind-claim":
        state_require(isinstance(p["members"], list) and 1 <= len(p["members"]) <= 128, "bound")
        for item in p["members"]:
            state_member(item)
        state_require(len({m["machine"] for m in p["members"]}) == len(p["members"]) and b["recipient"] in p["members"] and
                      p["participants_sha256"] == state_hash("broil-infra-participants-v1", [dict(m, node_uid=None) for m in p["members"]]))
    elif action == "prune-attempts":
        state_require(isinstance(p["attempts"], list) and p["attempts"])
        state_require(len(p["attempts"]) <= 1024, "bound")
        for item in p["attempts"]:
            state_hex(item)
        state_require(len(set(p["attempts"])) == len(p["attempts"]))
        state_uint(p["watermark_sequence"], 1)
    if action == "retire-writer":
        state_require(isinstance(p["seals"], list) and 1 <= len(p["seals"]) <= 128, "bound")
        for item in p["seals"]:
            state_fields(item, "machine generation seal_sha256")
            state_uint(item["generation"], 1)
            state_hex(item["seal_sha256"], 64)
    state_require(sys.stdin.buffer.read(1) == b"")


def state_main(raw, header):
    data = {k:None for k in ("claim", "reservation", "terminal", "seal", "retirement", "ownership", "resource", "identity", "failure")}
    if header.get("action") == "prune-attempts":
        data["history"] = None
    receiver = None
    status = "unknown"
    try:
        state_request(raw, header)
        receiver = StateReceiver(header)
        profile = receiver.profile()
        present = receiver.open(header["action"] == "reserve-owner")
        if not present:
            state_require(header["action"] == "inspect" and header["payload"]["subject"] == "owner", "ownership")
            receiver.no_installation()
            status = "absent"
        elif header["action"] == "inspect":
            status = receiver.inspect(data)
        else:
            functions = {"reserve-owner":receiver.reserve, "acquire-writer":receiver.acquire,
                         "admit-credential":receiver.grant, "seal-writer":receiver.seal, "retire-writer":receiver.retire,
                         "rebind-claim":receiver.rebind, "prune-attempts":receiver.prune}
            if header["action"] == "prepare-input":
                receiver.prepare_input(data, profile)
            else:
                functions[header["action"]](data)
            status = "ok"
    except (StateRefused, Refused, OSError, ValueError, KeyError, TypeError) as error:
        failure = error.failure if isinstance(error, StateRefused) else "integrity" if isinstance(error, (Refused, ValueError, KeyError, TypeError)) else "storage"
        data = {k:None for k in data}
        data["failure"] = failure
        status = "unknown" if EFFECTS else "busy" if failure == "busy" else "unsupported-version" if failure == "unsupported-version" else "bound" if failure == "bound" else "refused"
        if receiver is not None and receiver.intent is not None:
            try:
                data["terminal"] = receiver.terminal("failed", failure)
                status = "failed"
            except BaseException:
                status = "unknown"
    finally:
        if receiver is not None:
            for fd in (receiver.lock, receiver.root):
                if fd is not None:
                    os.close(fd)
    body = canonical({"version":1, "status":status, "data":data})
    frame = b"BK3SSTATE1\n" + struct.pack(">I", len(raw)) + raw + struct.pack(">I", len(body)) + body
    if len(frame) > MAXIMUM:
        os._exit(125)
    sys.stdout.buffer.write(frame)
    sys.stdout.buffer.flush()


def credential_writer(header, action):
    """Validate the one-use durable grant before reading any native slot."""
    path = ROOT + "/attempts/" + header["attempt"] + "/credentials/" + header["request_id"] + ".json"
    grant = state_read(path, "credential-grant")
    state_require(grant is not None, "ownership")
    binding = grant["binding"]
    state_binding(binding)
    projection = {k:v for k, v in header.items() if k not in ("remaining_ms", "slot_lengths")}
    member = header["source"] if action.startswith("read-") else header["destination"]
    state_require(grant["action"] == action and grant["admission_sha256"] == state_hash("broil-infra-credential-admission-v1", projection)
                  and grant["selection_sha256"] == header["selection_sha256"] and binding["dispatch"] == header["request_id"]
                  and all(binding[k] == header[k] for k in ("owner", "operation", "attempt"))
                  and all(binding["scope"][k] == header[k] for k in ("project", "environment", "target"))
                  and {k:binding["recipient"][k] for k in ("machine", "member", "role", "node_uid")} == member
                  and binding["fingerprints"]["profile_sha256"] == header["profile_sha256"]
                  and binding["fingerprints"]["script_sha256"] == header["script_sha256"], "ownership")
    resource = grant["resource"]
    state_require({k:resource[k] for k in ("kind", "id", "generation", "uid")} == header["resource"], "ownership")
    receiver = StateReceiver({"binding":binding, "action":"credential:" + action, "payload":projection})
    receiver.profile()
    state_require(receiver.open(False), "ownership")
    receiver.active()
    state_require(receiver.resource(resource)["identity"] is not None, "ownership")
    # A previous read cannot be repeated even if it has a terminal receipt.
    state_require(state_read(receiver.dispatch_path() + "/intent.json", "intent") is None, "ownership")
    return receiver, resource




# ---- Bootstrap application protocol ----
BOOT_ACTIONS = ("inspect-host", "inspect-generation", "prepare-generation", "download-asset", "receive-asset", "complete-generation")
BOOT_ROOT_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
BOOT_MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json")
BOOT_CONFIG_TYPES = ("application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json")
BOOT_LAYER_TYPES = ("application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip")
BOOT_GENERIC_LAYERS = BOOT_LAYER_TYPES + ("application/vnd.oci.image.layer.v1.tar",)
BOOT_CHECKS = ("host-profile", "canonical-access", "privilege", "tools", "sftp", "cgroups", "kernel", "swap", "capacity",
               "destination-storage", "interface", "dns", "routes", "clock", "ports", "foreign-installation", "existing-generation")
BOOT_TOOLS = ("/usr/bin/python3", "/usr/lib/openssh/sftp-server", "/usr/sbin/ip", "/usr/bin/timedatectl", "/usr/bin/systemctl", "/usr/bin/getent")
BOOT_PORTS = {"server": (6443, 9345, 2379, 2380, 10250, 10257, 10259, 80, 443), "agent": (10250,)}
INCOMING = "/var/lib/broil-k3s-incoming"
SFTP_SERVER = "/usr/lib/openssh/sftp-server"
BOOT_DATA = {}
BOOT_RESERVE = 16266
BUDGET = 0


def boot_document(name, encoded):
    """Decode one embedded data document; callers bind it to its pinned hash."""
    if name not in BOOT_DATA:
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        raw = decompressor.decompress(base64.b85decode(encoded), 65537)
        state_require(len(raw) <= 65536 and decompressor.eof and not decompressor.unused_data and raw.endswith(b"\n"), "bound")
        document = decode(raw[:-1])
        state_value(document)
        state_require(raw[:-1] == canonical(document))
        BOOT_DATA[name] = (raw, document)
    return BOOT_DATA[name]


def boot_index_sha256():
    return hashlib.sha256(boot_document("index", BOOT_INDEX)[0][:-1]).hexdigest()


def boot_index(index_sha256):
    state_require(boot_index_sha256() == index_sha256)
    raw, policy = boot_document("policy", BOOT_POLICY)
    index = BOOT_DATA["index"][1]
    state_require({"name": "airgap-descriptor-policy.lock.json", "sha256": hashlib.sha256(raw).hexdigest()} in index["inputs"])
    return index, policy


def boot_upstream(raw):
    """Parse one original OCI/Docker document under the upstream profile."""
    state_require(len(raw) <= 262144 and not raw.startswith(b"\xef\xbb\xbf"))
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    state_require(isinstance(value, dict))
    state_value(value)

    def walk(item):
        if isinstance(item, (dict, list)):
            state_require(len(item) <= 256, "bound")
            for child in item.values() if isinstance(item, dict) else item:
                walk(child)
        elif isinstance(item, int) and not isinstance(item, bool):
            state_require(item <= 4294967296)
    walk(value)
    return value


def boot_descriptor(value):
    state_require(isinstance(value, dict) and {"mediaType", "digest", "size"} <= set(value) <= {"mediaType", "digest", "size", "platform", "annotations"})
    state_require(isinstance(value["digest"], str) and re.fullmatch("sha256:[0-9a-f]{64}", value["digest"]) is not None)
    state_require(type(value["size"]) is int and 0 <= value["size"] <= 4294967296 and isinstance(value["mediaType"], str))
    platform = value.get("platform")
    if platform is not None:
        state_require(isinstance(platform, dict) and isinstance(platform.get("os"), str) and isinstance(platform.get("architecture"), str)
                      and set(platform) <= {"os", "architecture", "variant", "os.version", "os.features", "features"})
    annotations = value.get("annotations", {})
    state_require(isinstance(annotations, dict) and len(annotations) <= 16 and all(
        isinstance(k, str) and isinstance(v, str) and len(k.encode()) <= 256 and len(v.encode()) <= 1024 for k, v in annotations.items()))
    return value


def boot_pair(descriptor):
    platform = descriptor.get("platform")
    return (platform.get("os"), platform.get("architecture")) if isinstance(platform, dict) else None


class BootArchive:
    """Streamed outer-tar verification against the trusted inventory."""

    def __init__(self, asset):
        self.asset = asset
        self.inventory, self.names, self.retained, self.retained_bytes = [], set(), {}, 0
        self.consumed = self.expanded = 0

    def stream(self, fd, compressed):
        os.lseek(fd, 0, os.SEEK_SET)
        source = os.fdopen(os.dup(fd), "rb", closefd=True)
        return gzip.GzipFile(fileobj=source, mode="rb") if compressed else source

    def feed(self, fd, compressed):
        with self.stream(fd, compressed) as decoded:
            with tarfile.open(fileobj=decoded, mode="r|") as archive:
                for member in archive:
                    state_check()
                    self.member(archive, member)
                self.consumed = archive.offset
        # The complete decoded stream is measured independently of the tar
        # reader's buffering; every byte after the last entry must be zero.
        with self.stream(fd, compressed) as decoded:
            while chunk := decoded.read(1048576):
                state_check()
                start, self.expanded = self.expanded, self.expanded + len(chunk)
                if self.expanded > self.consumed:
                    state_require(not chunk[max(self.consumed - start, 0):].strip(b"\0"))
        trailer = self.expanded - self.consumed
        state_require(trailer >= 1024 and trailer % 512 == 0 and self.expanded == self.asset["expanded_bytes"]
                      and len(self.inventory) == self.asset["members"])
        state_require(hashlib.sha256(b"broil-k3s-bootstrap-content-v1\n" + canonical(self.inventory)).hexdigest() == self.asset["content_sha256"])
        self.files = {i["name"]: i for i in self.inventory if i["type"] == "file"}
        return self

    def member(self, archive, member):
        name = member.name
        parts = name.split("/")
        state_require(len(self.inventory) < self.asset["members"] and 0 < len(name.encode()) <= 4096 and name not in self.names
                      and not name.startswith("/") and not {"..", ".", ""} & set(parts) and not member.sparse
                      and not member.pax_headers and (member.isdir() or member.isfile()))
        self.names.add(name)
        if member.isdir():
            state_require(member.size == 0)
            self.inventory.append({"name": name, "type": "directory", "size": 0, "sha256": None})
            return
        keep = member.size <= 262144 and (name in ("index.json", "oci-layout", "manifest.json") or name.startswith("blobs/sha256/"))
        hasher, count, small = hashlib.sha256(), 0, bytearray()
        with archive.extractfile(member) as data:
            while chunk := data.read(1048576):
                count += len(chunk)
                state_require(count <= member.size)
                hasher.update(chunk)
                if keep:
                    small.extend(chunk)
        state_require(count == member.size)
        if keep:
            self.retained_bytes += len(small)
            state_require(self.retained_bytes <= 16777216, "bound")
            self.retained[name] = bytes(small)
        self.inventory.append({"name": name, "type": "file", "size": member.size, "sha256": hasher.hexdigest()})

    def present(self, descriptor, roles, visited):
        boot_descriptor(descriptor)
        name = "blobs/sha256/" + descriptor["digest"][7:]
        entry = self.files.get(name)
        state_require(entry is not None and entry["size"] == descriptor["size"] and entry["sha256"] == descriptor["digest"][7:]
                      and descriptor["mediaType"] in roles)
        visited.add(name)
        return name

    def document(self, name, descriptor):
        state_require(name in self.retained, "bound")
        value = boot_upstream(self.retained[name])
        state_require(value.get("mediaType", descriptor["mediaType"]) == descriptor["mediaType"])
        return value

    def runtime(self, descriptor, layers, visited):
        manifest = self.document(self.present(descriptor, BOOT_MANIFEST_TYPES, visited), descriptor)
        state_require(manifest.get("schemaVersion") == 2 and not {"subject", "artifactType"} & set(manifest))
        config = self.document(self.present(manifest["config"], BOOT_CONFIG_TYPES, visited), manifest["config"])
        state_require(config.get("os") == "linux" and config.get("architecture") == "amd64" and "variant" not in config)
        for layer in manifest["layers"]:
            self.present(layer, layers, visited)

    def closure(self, policy):
        visited = set()
        state_require("index.json" in self.retained)
        index = boot_upstream(self.retained["index.json"])
        roots = index["manifests"]
        state_require(index.get("schemaVersion") == 2 and roots)
        if policy is None:
            for root in roots:
                self.runtime(root, BOOT_GENERIC_LAYERS, visited)
        else:
            state_require("manifest.json" in self.files and "oci-layout" in self.files and roots == policy["roots"])
            edges = list(policy["metadata_only"])
            for position, root in enumerate(roots):
                document = self.document(self.present(root, BOOT_ROOT_TYPES, visited), root)
                entries = document["manifests"]
                admitted = [i for i, e in enumerate(entries) if boot_pair(boot_descriptor(e)) == ("linux", "amd64")]
                pinned = policy["runtime_manifests"][position]
                state_require(document.get("schemaVersion") == 2 and len(admitted) == 1 and pinned["parent"] == root["digest"]
                              and pinned["ordinal"] == admitted[0] and entries[admitted[0]] == pinned["descriptor"])
                others = {e["descriptor"]["digest"] for e in policy["metadata_only"] if e["parent"] == root["digest"] and e["reason"] == "other-platform"}
                for ordinal, entry in enumerate(entries):
                    if ordinal == admitted[0]:
                        state_require(set(entry["platform"]) == {"os", "architecture"})
                        self.runtime(entry, BOOT_LAYER_TYPES, visited)
                        continue
                    state_require(edges)
                    edge = edges.pop(0)
                    pair = boot_pair(entry)
                    state_require(edge["parent"] == root["digest"] and edge["ordinal"] == ordinal and edge["descriptor"] == entry
                                  and "blobs/sha256/" + entry["digest"][7:] not in self.files and pair is not None)
                    if edge["reason"] == "other-platform":
                        state_require(pair != ("linux", "amd64"))
                    else:
                        annotations = entry.get("annotations", {})
                        state_require(edge["reason"] == "attestation" and pair == ("unknown", "unknown") and len(entry["platform"]) == 2
                                      and annotations.get("vnd.docker.reference.type") == "attestation-manifest"
                                      and annotations.get("vnd.docker.reference.digest") in others | {entries[admitted[0]]["digest"]})
            state_require(not edges)
        state_require({n for n in self.files if n.startswith("blobs/")} == visited)


def boot_verify_file(fd, asset, policy):
    """Whole-file identity, then structure and closure for archives."""
    st = os.fstat(fd)
    state_require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size == asset["size"])
    os.lseek(fd, 0, os.SEEK_SET)
    hasher, total = hashlib.sha256(), 0
    while chunk := os.read(fd, 1048576):
        state_check()
        total += len(chunk)
        hasher.update(chunk)
    state_require(total == asset["size"] and hasher.hexdigest() == asset["sha256"])
    if asset["format"] != "raw":
        archive = BootArchive(asset).feed(fd, asset["format"] == "tar-gzip")
        # The Syncthing release archive is no image: its inventory is its whole structure.
        if asset["id"] != "syncthing":
            archive.closure(policy if policy["asset"] == asset["id"] else None)
    after = os.fstat(fd)
    state_require((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
    return [st.st_dev, st.st_ino]


def boot_copy(out, asset, chunks):
    """Stream verified bytes into an exclusive root partial; exact size and digest."""
    hasher, total = hashlib.sha256(), 0
    for chunk in chunks:
        state_check()
        total += len(chunk)
        state_require(total <= asset["size"])
        hasher.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(out, view)
            state_require(written > 0, "storage")
            view = view[written:]
    state_require(total == asset["size"] and hasher.hexdigest() == asset["sha256"])
    os.fsync(out)


def boot_read(path, limit=65536):
    try:
        with open(path, "rb") as stream:
            return stream.read(limit + 1)[:limit]
    except OSError:
        return b""


def boot_run(args):
    left = BUDGET - time.monotonic()
    state_require(left > 0, "timeout")
    result = subprocess.run(args, capture_output=True, timeout=left, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    state_require(len(result.stdout) < 65536, "bound")
    return result.returncode, result.stdout[:65536].decode("ascii", "replace")


def boot_listeners():
    found = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"):
        lines = boot_read(path, 1048576).decode("ascii", "replace").splitlines()[1:]
        state_require(len(lines) <= 4096, "bound")
        for fields in map(str.split, lines):
            if len(fields) > 3 and ("udp" in path or fields[3] == "0A"):
                found.add(("udp" if "udp" in path else "tcp", int(fields[1].rsplit(":", 1)[1], 16)))
    return found


class BootReceiver(StateReceiver):
    def __init__(self, header):
        StateReceiver.__init__(self, {"binding": header["binding"], "action": "bootstrap:" + header["action"], "payload": header["payload"]})
        self.tag = header["action"]
        self.recipe = header["payload"]["recipe"]
        self.resource = header["payload"]["resource"]
        self.asset = header["payload"]["asset"]
        self.index, self.policy = boot_index(self.recipe["index_sha256"])
        self.recipe_hash = state_hash("broil-k3s-bootstrap-recipe-v1", self.recipe)
        b, r = self.binding, self.resource
        state_require(all(self.recipe[k] == b[k] for k in ("scope", "owner", "operation", "attempt")) and b["recipient"] in self.recipe["members"]
                      and r in self.recipe["resources"] and r["kind"] == "bootstrap-assets" and r["owner"] == b["owner"]
                      and r["machine"] == r["id"] == b["recipient"]["machine"], "ownership")
        state_require({"name": "bootstrap-recipe", "sha256": self.recipe_hash} in b["fingerprints"]["tools"], "ownership")
        self.directory = f"{ROOT}/owners/{b['owner']}/assets/{r['generation']}"
        state_require(r["path"] == self.directory + "/", "ownership")
        declared = self.recipe["manifest"]["assets"]
        self.selected = [a for a in self.index["assets"] if a["when"] == "always" or len(declared) == len(self.index["assets"])]
        state_require([a["id"] for a in self.selected] == [a["id"] for a in declared])
        for pinned, entry in zip(self.selected, declared):
            state_require(all(entry[k] == pinned[k] for k in ("size", "sha256", "origin")) and (entry["url"] is None) == (self.recipe["mode"] == "bundle"))
        single = self.tag in ("download-asset", "receive-asset")
        state_require((self.asset is not None) == single and (not single or any(a["id"] == self.asset for a in self.selected)))

    def pinned(self):
        return next(a for a in self.selected if a["id"] == self.asset)

    def declared(self):
        return next(a for a in self.recipe["manifest"]["assets"] if a["id"] == self.asset)

    # -- host facts ------------------------------------------------------
    def facts(self):
        role, route = self.binding["recipient"]["role"], self.binding["recipient"]["route"]
        host = next((h for h in self.recipe["hosts"] if h["machine"] == self.binding["recipient"]["machine"]), None)
        state_require(host is not None, "ownership")
        network = self.recipe["network"]
        cidrs = [ipaddress.ip_network(network[k]) for k in ("pod_cidr", "service_cidr")]
        values = dict.fromkeys(("logical_cpus", "memory_bytes", "available_bytes", "available_inodes", "required_bytes", "required_inodes", "mount_identity"))
        values.update(os="unknown", release="unknown", architecture="unknown", init="unknown")

        def host_profile():
            release = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', boot_read("/etc/os-release").decode("utf-8", "replace"), re.M))
            values["os"] = "ubuntu" if release.get("ID") == "ubuntu" else "other"
            values["release"] = "24.04" if release.get("VERSION_ID") == "24.04" else "other"
            values["architecture"] = "amd64" if os.uname().machine == "x86_64" else "other"
            values["init"] = "systemd" if boot_read("/proc/1/comm").strip() == b"systemd" else "other"
            return (values["os"], values["release"], values["architecture"], values["init"]) == ("ubuntu", "24.04", "amd64", "systemd")

        def canonical_access():
            user = pwd.getpwnam(route["account"])
            home = "/root" if route["account"] == "root" else "/home/" + route["account"]
            return (route["account"] == "root") == (user.pw_uid == 0) and user.pw_dir == home and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", route["account"]) is not None

        def kernel():
            return (b"\toverlay\n" in boot_read("/proc/filesystems") and os.path.exists("/proc/sys/net/bridge/bridge-nf-call-iptables")
                    and boot_read("/proc/sys/net/ipv4/ip_forward").strip() == b"1")

        def capacity():
            meminfo = dict(re.findall(r"^(\w+):\s+(\d+) kB", boot_read("/proc/meminfo").decode("ascii", "replace"), re.M))
            values["logical_cpus"], values["memory_bytes"] = os.cpu_count() or 0, int(meminfo["MemTotal"]) * 1024
            floor = (2, 2147483648) if role == "server" else (1, 536870912)
            values["required_bytes"] = sum(a["size"] + a["expanded_bytes"] for a in self.selected) + max(a["size"] for a in self.selected) + 1073741824
            values["required_inodes"] = 20 + 2 * len(self.selected) + sum(a["members"] for a in self.selected)
            fs = os.statvfs(self.existing_parent())
            values["available_bytes"], values["available_inodes"] = fs.f_bavail * fs.f_frsize, fs.f_favail
            return (values["logical_cpus"] >= floor[0] and values["memory_bytes"] >= floor[1]
                    and values["available_bytes"] >= values["required_bytes"] and values["available_inodes"] >= values["required_inodes"])

        def destination_storage():
            parent = self.existing_parent()
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
            try:
                values["mount_identity"] = identity(fd)
            finally:
                os.close(fd)
            lines = boot_read("/proc/self/mountinfo", 1048576).decode("utf-8", "replace").splitlines()
            state_require(len(lines) <= 4096, "bound")
            best = None
            for line in lines:
                left, _, right = line.partition(" - ")
                point = left.split()[4]
                if (parent + "/").startswith(point.rstrip("/") + "/") and (best is None or len(point) > len(best[0])):
                    best = (point, right.split()[0])
            return best is not None and best[1] in ("ext4", "xfs", "btrfs")

        def interface():
            code, out = boot_run(["/usr/sbin/ip", "-4", "-o", "addr", "show", "dev", host["interface"]])
            return code == 0 and any(" inet " + host["node_ip"] + "/" in " " + line for line in out.splitlines())

        def dns():
            names = network["endpoints"]
            for start in range(0, len(names), 16):
                code, out = boot_run(["/usr/bin/getent", "ahostsv4", "--", *names[start:start + 16]])
                if code != 0 or any(ipaddress.ip_address(line.split()[0]) in cidr for line in out.splitlines() for cidr in cidrs):
                    return False
            return True

        def routes():
            code, out = boot_run(["/usr/sbin/ip", "-4", "route", "show"])
            if code != 0 or any(ipaddress.ip_network(prefix).overlaps(cidr) for prefix in re.findall(r"^(?:\w+ )?(\d\S*)", out, re.M) for cidr in cidrs):
                return False
            for peer in self.recipe["hosts"]:
                if peer is not host and boot_run(["/usr/sbin/ip", "-4", "route", "get", peer["node_ip"]])[0] != 0:
                    return False
            return True

        def clock():
            code, out = boot_run(["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"])
            return code == 0 and out.strip() == "yes"

        def foreign():
            return not any(os.path.lexists(p) for p in ("/var/lib/rancher/k3s", "/etc/rancher/k3s", "/usr/local/bin/k3s", "/run/k3s",
                                                        "/etc/systemd/system/k3s.service", "/etc/systemd/system/k3s-agent.service"))

        def existing():
            try:
                fd = state_directory(self.directory)
            except FileNotFoundError:
                return True
            try:
                marker = state_read(self.directory + "/complete.json")
                return marker is not None and marker.get("recipe_sha256") == self.recipe_hash and marker.get("resource") == self.resource
            finally:
                os.close(fd)

        probes = {"host-profile": host_profile, "canonical-access": canonical_access, "privilege": lambda: os.geteuid() == 0,
                  "tools": lambda: all(os.path.isfile(p) and os.access(p, os.X_OK) for p in BOOT_TOOLS),
                  "sftp": lambda: os.path.isfile(SFTP_SERVER) and os.access(SFTP_SERVER, os.X_OK),
                  "cgroups": lambda: {b"cpu", b"memory", b"pids"} <= set(boot_read("/sys/fs/cgroup/cgroup.controllers").split()),
                  "kernel": kernel, "swap": lambda: len(boot_read("/proc/swaps").splitlines()) <= 1, "capacity": capacity,
                  "destination-storage": destination_storage, "interface": interface, "dns": dns, "routes": routes, "clock": clock,
                  "ports": lambda: not boot_listeners() & ({("tcp", p) for p in BOOT_PORTS[role]} | {("udp", 8472)}),
                  "foreign-installation": foreign, "existing-generation": existing}
        global BUDGET
        checks = []
        for name in BOOT_CHECKS:
            state_check()
            BUDGET = min(time.monotonic() + 10, DEADLINE - 1)
            try:
                status = "pass" if probes[name]() else "fail"
            except Exception:
                status = "unknown"
            checks.append({"check": name, "status": status})
        values["checks"] = checks
        return values

    def existing_parent(self):
        path = self.directory
        while not os.path.isdir(path):
            path = os.path.dirname(path)
        return path

    # -- generation directory -----------------------------------------------
    def generation(self, create=False):
        self.active()
        owner = f"{ROOT}/owners/{self.binding['owner']}"
        state_mkdir(owner)
        state_mkdir(owner + "/assets")
        parent = state_directory(owner + "/assets")
        try:
            if create:
                os.mkdir(self.resource["generation"], 0o700, dir_fd=parent)
                os.fsync(parent)
            fd = os.open(self.resource["generation"], os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            state_private(fd, True)
            expected = {"schema": 1, "kind": "bootstrap-generation", "recipe_sha256": self.recipe_hash, "resource": self.resource, "directory": identity(fd)}
            binding = state_read(self.directory + "/binding.json")
            if create:
                state_require(binding is None, "ownership")
                state_publish(self.directory + "/binding.json", expected)
                os.fsync(fd)  # Actual write and fsync support on the destination.
                binding = expected
            state_require(binding == expected, "ownership")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def children(self, fd):
        names = sorted(os.listdir(fd))
        allowed = {"binding.json", "complete.json"} | {a["filename"] for a in self.selected}
        state_require(len(names) <= 64 and all(n in allowed or n.startswith(".partial-") for n in names), "ownership")
        return names

    def publish(self, fd, asset, chunks):
        """Exclusive root partial, independent verification, publication without replacement, parent fsync."""
        partial = ".partial-" + self.binding["dispatch"]
        out = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=fd)
        try:
            state_private(out)
            boot_copy(out, asset, chunks)
            boot_verify_file(out, asset, self.policy)
            os.link(partial, asset["filename"], src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(partial, dir_fd=fd)
            os.fsync(fd)
            return identity(out)
        finally:
            os.close(out)

    def finish_asset(self, data, ident):
        data["assets"].append({"resource": self.resource, "asset": self.asset, "identity": ident, "state": "verified"})
        data["terminal"] = self.terminal("succeeded", None, self.resource, ident)

    def marker(self, fd, identities):
        b = self.binding
        return {"schema": 1, "kind": "bootstrap-complete", "scope": b["scope"], "owner": b["owner"], "operation": b["operation"],
                "attempt": b["attempt"], "resource": self.resource, "recipe_sha256": self.recipe_hash, "directory": identity(fd), "inactive": True,
                "assets": [{"id": a["id"], "size": a["size"], "sha256": a["sha256"], "identity": i} for a, i in zip(self.selected, identities)]}

    # -- actions --------------------------------------------------------------
    def inspect_generation(self, data):
        try:
            fd = state_directory(self.directory)
        except FileNotFoundError:
            return "absent"
        try:
            marker = state_read(self.directory + "/complete.json")
            for asset in self.selected:
                event = {"resource": self.resource, "asset": asset["id"], "identity": None, "state": "absent"}
                try:
                    afd = os.open(asset["filename"], os.O_RDONLY | NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    data["assets"].append(event)
                    continue
                try:
                    event.update(identity=identity(afd), state="verified" if marker is not None else "received")
                    state_private(afd)
                finally:
                    os.close(afd)
                data["assets"].append(event)
            if marker is not None:
                state_require(canonical(marker) == canonical(self.marker(fd, [e["identity"] for e in data["assets"]])), "ownership")
                data["marker"] = marker
            return "ok"
        finally:
            os.close(fd)

    def prepare_generation(self, data):
        self.active()
        state_require(self.begin() is None, "ownership")
        self.effect_started = True
        fd = self.generation(create=True)
        try:
            data["terminal"] = self.terminal("succeeded", None, self.resource, identity(fd))
        finally:
            os.close(fd)

    def download_asset(self, data):
        self.active()
        state_require(self.begin() is None, "ownership")
        fd = self.generation()
        try:
            asset, declared = self.pinned(), self.declared()
            state_require(asset["filename"] not in self.children(fd), "ownership")
            state_require(self.recipe["mode"] == "online" and isinstance(declared["url"], str) and declared["url"].startswith("https://"), "capability")
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy"):
                os.environ.pop(name, None)
            # No redirect handler: any 3xx is an error, never a second location.
            opener = urllib.request.OpenerDirector()
            for handler in (urllib.request.HTTPSHandler(context=ssl.create_default_context()), urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
                opener.add_handler(handler)
            self.effect_started = True

            def chunks():
                with opener.open(urllib.request.Request(declared["url"], headers={"User-Agent": "broil-k3s-bootstrap/1"}),
                                 timeout=min(30, max(0.01, DEADLINE - time.monotonic()))) as response:
                    state_require(response.status == 200, "transport")
                    while chunk := response.read(1048576):
                        yield chunk
            self.finish_asset(data, self.publish(fd, asset, chunks()))
        finally:
            os.close(fd)

    def receive_asset(self, data, ready):
        state_require(self.recipe["mode"] == "bundle", "capability")
        self.active()
        state_require(self.begin() is None, "ownership")
        fd = self.generation()
        try:
            asset, account = self.pinned(), self.binding["recipient"]["route"]["account"]
            state_require(asset["filename"] not in self.children(fd), "ownership")
            user = pwd.getpwnam(account)
            state_require(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", account) is not None and (account == "root") == (user.pw_uid == 0), "ownership")
            # Root-owned 0711 dispatch directory; canonical socket/data.
            base = f"{INCOMING}/{self.binding['owner']}/{self.binding['dispatch']}"
            os.umask(0o022)
            for path in (INCOMING, os.path.dirname(base)):
                os.makedirs(path, 0o711, exist_ok=True)
                os.chmod(path, 0o711)
            os.mkdir(base, 0o711)
            os.umask(0o077)
            dfd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
            try:
                st = os.fstat(dfd)
                state_require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o711, "ownership")
                os.mkdir("data", 0o700, dir_fd=dfd)
                os.chown("data", user.pw_uid, user.pw_gid, dir_fd=dfd)
                data_fd = os.open("data", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=dfd)
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(base + "/socket")
                os.chown(base + "/socket", user.pw_uid, user.pw_gid, follow_symlinks=False)
                os.chmod(base + "/socket", 0o600)
                listener.listen(1)
                sock = os.stat("socket", dir_fd=dfd, follow_symlinks=False)
                record = {"schema": 1, "kind": "bootstrap-input", "binding": self.binding, "resource": self.resource, "asset": self.asset,
                          "size": asset["size"], "sha256": asset["sha256"], "recipe_sha256": self.recipe_hash, "account": account,
                          "uid": user.pw_uid, "gid": user.pw_gid, "directory": identity(dfd), "socket": [sock.st_dev, sock.st_ino],
                          "temporary": "upload.tmp", "destination": "received"}
                self.revalidate()
                state_publish(self.dispatch_path() + "/bootstrap-input.json", record)
                self.effect_started = True
                ready(record)
                listener.settimeout(max(0.01, DEADLINE - time.monotonic()))
                connection, _ = listener.accept()
                listener.close()
                os.unlink("socket", dir_fd=dfd)
                credentials = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                state_require(credentials[1] == user.pw_uid and credentials[2] == user.pw_gid, "ownership")
                connection.settimeout(max(0.01, DEADLINE - time.monotonic()))
                handshake = b""
                while len(handshake) < 73:
                    chunk = connection.recv(73 - len(handshake))
                    state_require(chunk, "transport")
                    handshake += chunk
                state_require(handshake == b"BK3SUP1\n" + state_hash("broil-k3s-bootstrap-input-v1", record).encode() + b"\n", "ownership")
                # The stock writer inherits the held state lock through exit.
                child = subprocess.Popen([SFTP_SERVER, "-e", "-d", base + "/data"], stdin=connection.fileno(), stdout=connection.fileno(),
                                         stderr=subprocess.DEVNULL, cwd=base + "/data", user=user.pw_uid, group=user.pw_gid, extra_groups=[],
                                         env={"PATH": "/usr/bin:/bin", "HOME": user.pw_dir, "LANG": "C.UTF-8"}, pass_fds=(self.lock,))
                connection.close()
                try:
                    code = child.wait(timeout=max(0.01, DEADLINE - time.monotonic()))
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                    raise StateRefused("timeout")
                state_require(code == 0 and sorted(os.listdir(data_fd)) == ["received"], "transport")
                received = os.open("received", os.O_RDONLY | NOFOLLOW, dir_fd=data_fd)
                try:
                    rst = os.fstat(received)
                    state_require(stat.S_ISREG(rst.st_mode) and rst.st_nlink == 1 and rst.st_uid == user.pw_uid
                                  and stat.S_IMODE(rst.st_mode) == 0o600 and rst.st_size == asset["size"])
                    boot_verify_file(received, asset, self.policy)
                    os.lseek(received, 0, os.SEEK_SET)
                    ident = self.publish(fd, asset, iter(lambda: os.read(received, 1048576), b""))
                finally:
                    os.close(received)
                os.unlink("received", dir_fd=data_fd)
                os.close(data_fd)
                os.rmdir("data", dir_fd=dfd)
            finally:
                os.close(dfd)
            os.rmdir(base)
            self.finish_asset(data, ident)
        finally:
            os.close(fd)

    def complete_generation(self, data):
        self.active()
        state_require(self.begin() is None, "ownership")
        fd = self.generation()
        try:
            state_require(self.children(fd) == sorted(["binding.json"] + [a["filename"] for a in self.selected]), "ownership")
            identities = []
            for asset in self.selected:
                afd = os.open(asset["filename"], os.O_RDONLY | NOFOLLOW, dir_fd=fd)
                try:
                    state_private(afd)
                    identities.append(boot_verify_file(afd, asset, self.policy))
                finally:
                    os.close(afd)
            marker = self.marker(fd, identities)
            self.effect_started = True
            self.revalidate()
            state_publish(self.directory + "/complete.json", marker)
            os.fsync(fd)
            data["marker"] = marker
            data["terminal"] = self.terminal("succeeded", None, self.resource, identity(fd))
        finally:
            os.close(fd)


def boot_request(raw, header):
    global DEADLINE
    state_require(14 + len(raw) + BOOT_RESERVE <= 65536, "bound")
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms payload")
    state_require(header["protocol"] == "broil-k3s-bootstrap" and canonical(header) == raw)
    state_require(type(header["version"]) is int and header["version"] == 1,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
    state_require(header["action"] in BOOT_ACTIONS, "capability")
    state_hex(header["request_id"])
    state_binding(header["binding"])
    mutation = header["action"] not in BOOT_ACTIONS[:2]
    state_uint(header["remaining_ms"], 1, 7200000 if mutation else 30000)
    state_require((header["request_id"] == header["binding"]["dispatch"]) == mutation)
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    p = header["payload"]
    state_fields(p, "recipe resource asset")
    state_require(len(canonical(header["binding"])) <= 4096 and len(canonical(p["resource"])) <= 512, "bound")
    recipe = p["recipe"]
    state_fields(recipe, "schema scope owner operation attempt members resources mode manifest index_sha256 hosts network")
    state_require(recipe["schema"] == 1 and recipe["mode"] in ("online", "bundle"))
    state_scope(recipe["scope"])
    state_members(recipe["members"], header["binding"])
    hosts, machines = recipe["hosts"], [m["machine"] for m in recipe["members"]]
    state_require(isinstance(hosts, list) and len(hosts) in (1, len(machines)))
    for host in hosts:
        state_fields(host, "machine interface node_ip")
        state_require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", host["interface"])
                      and str(ipaddress.IPv4Address(host["node_ip"])) == host["node_ip"])
    # One host per member in member order, or a replacement preparation's one selected member.
    state_require([h["machine"] for h in hosts] == machines or len(hosts) == 1 and hosts[0]["machine"] in machines)
    network = recipe["network"]
    state_fields(network, "pod_cidr service_cidr endpoints")
    for cidr in (network["pod_cidr"], network["service_cidr"]):
        state_require(str(ipaddress.IPv4Network(cidr)) == cidr)
    names = network["endpoints"]
    state_require(names == sorted(set(names)) and all(re.fullmatch(r"[a-z0-9.-]{1,253}", n) for n in names))
    state_hex(recipe["index_sha256"], 64)
    state_fields(recipe["manifest"], "schema profile_sha256 platform version assets")
    state_require(recipe["manifest"]["schema"] == 1 and recipe["manifest"]["platform"] == "linux/amd64"
                  and recipe["manifest"]["profile_sha256"] == header["binding"]["fingerprints"]["profile_sha256"])
    state_require(isinstance(recipe["resources"], list) and 1 <= len(recipe["resources"]) <= 128, "bound")
    for resource in recipe["resources"]:
        state_fields(resource, "kind id owner generation machine path namespace name uid")
        state_hex(resource["generation"])
    state_require(p["resource"] in recipe["resources"], "ownership")
    state_require(p["asset"] is None or (isinstance(p["asset"], str) and re.fullmatch("[a-z0-9][a-z0-9-]{0,63}", p["asset"]) is not None))
    state_require(sys.stdin.buffer.read(1) == b"")


def boot_main(raw, header):
    frames, receiver, status = [], None, "unknown"
    data = {"terminal": None, "facts": None, "assets": [], "marker": None, "failure": None}
    prefix = b"BK3SBOOT1\n" + struct.pack(">I", len(raw)) + raw

    def frame(value):
        body = canonical(value)
        frames.append(struct.pack(">I", len(body)) + body)
        return frames[-1]

    def ready(record):
        sys.stdout.buffer.write(prefix + frame({"kind": "ready", "input": record, "binding_sha256": state_hash("broil-k3s-bootstrap-input-v1", record)}))
        sys.stdout.buffer.flush()
    try:
        boot_request(raw, header)
        receiver = BootReceiver(header)
        receiver.profile()
        present = receiver.open(False)
        tag = header["action"]
        if tag == "inspect-host":
            data["facts"] = receiver.facts()
            status = "ok"
        else:
            state_require(present, "ownership")
            if tag == "inspect-generation":
                status = receiver.inspect_generation(data)
            else:
                {"prepare-generation": receiver.prepare_generation, "download-asset": receiver.download_asset, "complete-generation": receiver.complete_generation,
                 "receive-asset": lambda d: receiver.receive_asset(d, ready)}[tag](data)
                status = "ok"
    except Exception as error:
        failure = error.failure if isinstance(error, StateRefused) else "storage" if isinstance(error, OSError) else "transport" if isinstance(error, subprocess.SubprocessError) else "integrity"
        data = {"terminal": None, "facts": None, "assets": [], "marker": None, "failure": failure}
        status = "unknown" if EFFECTS else "busy" if failure == "busy" else "unsupported-version" if failure == "unsupported-version" else "bound" if failure == "bound" else "refused"
        if receiver is not None and receiver.intent is not None:
            try:
                data["terminal"] = receiver.terminal("failed", failure)
                status = "failed"
            except BaseException:
                status = "unknown"
    finally:
        if receiver is not None:
            for fd in (receiver.lock, receiver.root):
                if fd is not None:
                    os.close(fd)
    result = frame({"kind": "result", "status": status, **data})
    if len(prefix) + sum(map(len, frames)) > 65536:
        os._exit(125)
    sys.stdout.buffer.write((b"" if len(frames) == 2 else prefix) + result)
    sys.stdout.buffer.flush()


def sftp_launcher(args):
    """Canonical relay: connect once after validated readiness, send the 73-byte
    public handshake, then move SFTP bytes between stdio and the socket."""
    if len(args) != 3 or not all(re.fullmatch("[0-9a-f]{32}", a) for a in args[:2]) or not re.fullmatch("[0-9a-f]{64}", args[2]) or sum(map(len, args)) + 24 > 256:
        return 76
    try:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(30)
        connection.connect(f"{INCOMING}/{args[0]}/{args[1]}/socket")
        connection.settimeout(None)
        connection.sendall(b"BK3SUP1\n" + args[2].encode() + b"\n")
    except OSError:
        return 77
    stdin, stdout = sys.stdin.buffer.raw, sys.stdout.buffer.raw
    selector = selectors.DefaultSelector()
    selector.register(stdin, selectors.EVENT_READ, "in")
    selector.register(connection, selectors.EVENT_READ, "sock")
    ends = 2
    while ends:
        for key, _ in selector.select():
            chunk = stdin.read(65536) if key.data == "in" else connection.recv(65536)
            if not chunk:
                selector.unregister(stdin if key.data == "in" else connection)
                ends -= 1
                if key.data == "in":
                    connection.shutdown(socket.SHUT_WR)
                else:
                    ends = 0
            elif key.data == "in":
                connection.sendall(chunk)
            else:
                stdout.write(chunk)
                stdout.flush()
    connection.close()
    return 0


raw = None
credential_receiver = None
if sys.argv[1:2] == ["--broil-k3s-sftp-v1"]:
    os._exit(sftp_launcher(sys.argv[2:]))
try:
    os.umask(0o077)
    raw, header, action, inspect = request()
    if not inspect:
        credential_receiver, credential_resource = credential_writer(header, action)
    generation, record, executable = admit(header, action)
    if credential_receiver is not None:
        state_require(credential_receiver.begin() is None, "ownership")
        credential_receiver.effect_started = True
    kind, data = apply(header, action, inspect, generation, record, executable)
    if credential_receiver is not None:
        credential_receiver.terminal("succeeded", None, credential_resource)
    status = 0
except Refused as error:
    status, kind, data = (6 if EFFECTS else error.code), 0, b""
except Exception:
    status, kind, data = (6 if EFFECTS else 1), 0, b""
if credential_receiver is not None and status != 0 and credential_receiver.intent is not None:
    try:
        credential_receiver.terminal("failed", "credential")
    except BaseException:
        status = 6
if raw is None:
    os._exit(125)
sys.stdout.buffer.write(b"BK3S1\n" + struct.pack(">I", len(raw)) + raw + bytes([status, kind]) + struct.pack(">I", len(data)) + data)
sys.stdout.buffer.flush()
