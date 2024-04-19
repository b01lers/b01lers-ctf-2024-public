# Writeup for bash cat with pipe by ky28059

> My terminal seems to be stuck... please help me fix it!

We're given a shell prompt, but every command we type is prepended with
```
cat with |
```
To see what the contents of `with` that we're dealing with are, we can run
```
cat with | cat
```

![image](https://github.com/b01lers/b01lers-ctf-2024/assets/60120929/185977f8-4241-4bf1-a204-78e6d4684691)

Beautiful, isn't it?

The big clue here is the "hint" conveniently injected into the cantilever Wikipedia article. Of course, we can run
```bash
kevin@ky28059:~$ nc localhost 7072
$ cat with | ls
flag.txt
run
with
```
to verify it, but some easy solutions have already been disallowed.
```bash
kevin@ky28059:~$ nc localhost 7072
$ cat with | cat flag.txt
disallowed: flag
```
```bash
kevin@ky28059:~$ nc localhost 7072
$ cat with | cat ????.txt
disallowed: ?
```
```bash
kevin@ky28059:~$ nc localhost 7072
$ cat with | cat [^0][^0][^0][^0].txt
disallowed: [
```
The main idea is that we can use `xargs cat` to pipe every word in the file into `cat` and run it, one of which is `flag.txt`.
Unfortunately, there are too many words in the file by default, so just doing this by itself exceeds the `xargs` buffer size
and `cat` never reaches `flag.txt` at the end of the file.
```bash
kevin@ky28059:~$ nc localhost 7072
$ cat with | xargs cat
xargs: unmatched single quote; by default quotes are special to xargs unless you use the -0 option
cat: A: No such file or directory
cat: cantilever: No such file or directory
cat: is: No such file or directory
cat: a: No such file or directory
cat: rigid: No such file or directory
cat: structural: No such file or directory
cat: element: No such file or directory
cat: that: No such file or directory
cat: extends: No such file or directory
cat: horizontally: No such file or directory
cat: and: No such file or directory
cat: is: No such file or directory
cat: unsupported: No such file or directory
cat: at: No such file or directory
cat: one: No such file or directory
cat: end.: No such file or directory
cat: Typically: No such file or directory
cat: it: No such file or directory
cat: extends: No such file or directory
cat: from: No such file or directory
cat: a: No such file or directory
cat: flat: No such file or directory
cat: vertical: No such file or directory
cat: surface: No such file or directory
cat: such: No such file or directory
cat: as: No such file or directory
cat: a: No such file or directory
cat: wall,: No such file or directory
cat: to: No such file or directory
cat: which: No such file or directory
cat: it: No such file or directory
cat: must: No such file or directory
cat: be: No such file or directory
cat: firmly: No such file or directory
cat: attached.: No such file or directory
cat: Like: No such file or directory
cat: other: No such file or directory
cat: structural: No such file or directory
cat: elements,: No such file or directory
cat: a: No such file or directory
cat: cantilever: No such file or directory
cat: can: No such file or directory
cat: be: No such file or directory
cat: formed: No such file or directory
cat: as: No such file or directory
cat: a: No such file or directory
cat: beam,: No such file or directory
cat: plate,: No such file or directory
cat: truss,: No such file or directory
cat: or: No such file or directory
cat: slab.: No such file or directory
cat: When: No such file or directory
cat: subjected: No such file or directory
cat: to: No such file or directory
cat: a: No such file or directory
cat: structural: No such file or directory
cat: load: No such file or directory
cat: at: No such file or directory
cat: its: No such file or directory
cat: far,: No such file or directory
cat: unsupported: No such file or directory
cat: end,: No such file or directory
cat: the: No such file or directory
cat: cantilever: No such file or directory
cat: carries: No such file or directory
cat: the: No such file or directory
cat: load: No such file or directory
cat: to: No such file or directory
cat: the: No such file or directory
cat: support: No such file or directory
cat: where: No such file or directory
cat: it: No such file or directory
cat: applies: No such file or directory
cat: a: No such file or directory
cat: shear: No such file or directory
cat: stress: No such file or directory
cat: and: No such file or directory
cat: a: No such file or directory
cat: bending: No such file or directory
cat: 'moment.[1]': No such file or directory
cat: Cantilever: No such file or directory
cat: construction: No such file or directory
cat: allows: No such file or directory
cat: overhanging: No such file or directory
cat: structures: No such file or directory
cat: without: No such file or directory
cat: additional: No such file or directory
cat: support.: No such file or directory
cat: Cantilevers: No such file or directory
cat: are: No such file or directory
cat: widely: No such file or directory
cat: found: No such file or directory
cat: in: No such file or directory
cat: construction,: No such file or directory
cat: notably: No such file or directory
cat: in: No such file or directory
cat: cantilever: No such file or directory
cat: bridges: No such file or directory
cat: and: No such file or directory
cat: balconies: No such file or directory
cat: '(see': No such file or directory
cat: 'corbel).': No such file or directory
cat: In: No such file or directory
cat: cantilever: No such file or directory
cat: bridges,: No such file or directory
cat: the: No such file or directory
cat: cantilevers: No such file or directory
cat: are: No such file or directory
cat: usually: No such file or directory
cat: built: No such file or directory
cat: as: No such file or directory
cat: pairs,: No such file or directory
A cantilever is a rigid structural element that extends horizontally and is unsupported at one end. Typically it extends from a flat vertical surface such as a wall, to which it must be firmly attached. Like other structural elements, a cantilever can be formed as a beam, plate, truss, or slab.

When subjected to a structural load at its far, unsupported end, the cantilever carries the load to the support where it applies a shear stress and a bending moment.[1]

Cantilever construction allows overhanging structures without additional support.

Cantilevers are widely found in construction, notably in cantilever bridges and balconies (see corbel). In cantilever bridges, the cantilevers are usually built as pairs, with each cantilever used to support one end of a central section. The Forth Bridge in Scotland is an example of a cantilever truss bridge. A cantilever in a traditionally timber framed building is called a jetty or forebay. In the southern United States, a historic barn type is the cantilever barn of log construction.

Temporary cantilevers are often used in construction. The partially constructed structure creates a cantilever, but the completed structure does not act as a cantilever. This is very helpful when temporary supports, or falsework, cannot be used to support the structure while it is being built (e.g., over a busy roadway or river, or in a deep valley). Therefore, some truss arch bridges (see Navajo Bridge) are built from each side as cantilevers until the spans reach each other and are then jacked apart to stress them in compression before finally joining. Nearly all cable-stayed bridges are built using cantilevers as this is one of their chief advantages. Many box girder bridges are built segmentally, or in short pieces. This type of construction lends itself well to balanced cantilever construction where the bridge is built in both directions from a single support.

These structures rely heavily on torque and rotational equilibrium for their stability.

In an architectural application, Frank Lloyd Wright's Fallingwater used cantilevers to project large balconies. The East Stand at Elland Road Stadium in Leeds was, when completed, the largest cantilever stand in the world[2] holding 17,000 spectators. The roof built over the stands at Old Trafford uses a cantilever so that no supports will block views of the field. The old (now demolished) Miami Stadium had a similar roof over the spectator area. The largest cantilevered roof in Europe is located at St James' Park in Newcastle-Upon-Tyne, the home stadium of Newcastle United F.C.[3][4]

Less obvious examples of cantilevers are free-standing (vertical) radio towers without guy-wires, and chimneys, which resist being blown over by the wind through cantilever action at their base.

The cantilever is commonly used in the wings of fixed-wing aircraft. Early aircraft had light structures which were braced with wires and struts. However, these introduced aerodynamic drag which limited performance. While it is heavier, the cantilever avoids this issue and allows the plane to fly faster.

Hugo Junkers pioneered the cantilever wing in 1915. Only a dozen years after the Wright Brothers' initial flights, Junkers endeavored to eliminate virtually all major external bracing members in order to decrease airframe drag in flight. The result of this endeavor was the Junkers J 1 pioneering all-metal monoplane of late 1915, designed from the start with all-metal cantilever wing panels. About a year after the initial success of the Junkers J 1, Reinhold Platz of Fokker also achieved success with a cantilever-winged sesquiplane built instead with wooden materials, the Fokker V.1.

In the cantilever wing, one or more strong beams, called spars, run along the span of the wing. The end fixed rigidly to the central fuselage is known as the root and the far end as the tip. In flight, the wings generate lift and the spars carry this load through to the fuselage.

To resist horizontal shear stress from either drag or engine thrust, the wing must also form a stiff cantilever in the horizontal plane. A single-spar design will usually be fitted with a second smaller drag-spar nearer the trailing edge, braced to the main spar via additional internal members or a stressed skin. The wing must also resist twisting forces, achieved by cross-bracing or otherwise stiffening the main structure.

Cantilever wings require much stronger and heavier spars than would otherwise be needed in a wire-braced design. However, as the speed of the aircraft increases, the drag of the bracing increases sharply, while the wing structure must be strengthened, typically by increasing the strength of the spars and the thickness of the skinning. At speeds of around 200 miles per hour (320 km/h) the drag of the bracing becomes excessive and the wing strong enough to be made a cantilever without excess weight penalty. Increases in engine power through the late 1920s and early 1930s raised speeds through this zone and by the late 1930s cantilever wings had almost wholly superseded braced ones.[5] Other changes such as enclosed cockpits, retractable undercarriage, landing flaps and stressed-skin construction furthered the design revolution, with the pivotal moment widely acknowledged to be the MacRobertson England-Australia air race of 1934, which was won by a de Havilland DH.88 Comet.[6]

Currently, cantilever wings are almost universal with bracing only being used for some slower aircraft where a lighter weight is prioritized over speed, such as in the ultralight class.

Cantilevered beams are the most ubiquitous structures in the field of microelectromechanical systems (MEMS). An early example of a MEMS cantilever is the Resonistor,[7][8] an electromechanical monolithic resonator. MEMS cantilevers are commonly fabricated from silicon (Si), silicon nitride (Si3N4), or polymers. The fabrication process typically involves undercutting the cantilever structure to release it, often with an anisotropic wet or dry etching technique. Without cantilever transducers, atomic force microscopy would not be possible. A large number of research groups are attempting to develop cantilever arrays as biosensors for medical diagnostic applications. MEMS cantilevers are also finding application as radio frequency filters and resonators. The MEMS cantilevers are commonly made as unimorphs or bimorphs.

Two equations are key to understanding the behavior of MEMS cantilevers. The first is Stoney's formula, which relates cantilever end deflection δ to applied stress σ:

[math equations]

The principal advantage of MEMS cantilevers is their cheapness and ease of fabrication in large arrays. The challenge for their practical application lies in the square and cubic dependences of cantilever performance specifications on dimensions. These superlinear dependences mean that cantilevers are quite sensitive to variation in process parameters, particularly the thickness as this is generally difficult to accurately measure.[9] However, it has been shown that microcantilever thicknesses can be precisely measured and that this variation can be quantified.[10] Controlling residual stress can also be difficult.

A chemical sensor can be obtained by coating a recognition receptor layer over the upper side of a microcantilever beam.[12] A typical application is the immunosensor based on an antibody layer that interacts selectively with a particular immunogen and reports about its content in a specimen. In the static mode of operation, the sensor response is represented by the beam bending with respect to a reference microcantilever. Alternatively, microcantilever sensors can be operated in the dynamic mode. In this case, the beam vibrates at its resonance frequency and a variation in this parameter indicates the concentration of the analyte. Recently, microcantilevers have been fabricated that are porous, allowing for a much larger surface area for analyte to bind to, increasing sensitivity by raising the ratio of the analyte mass to the device mass.[13] Surface stress on microcantilever, due to receptor-target binding, which produces cantilever deflection can be analyzed using optical methods like laser interferometry. Zhao et al., also showed that by changing the attachment protocol of the receptor on the microcantilever surface, the sensitivity can be further improved when the surface stress generated on the microcantilever is taken as the sensor signal.[14]

See also
- Applied mechanics
- Cantilever bicycle brakes
- Cantilever bicycle frame
- Cantilever chair
- Cantilever method
- Cantilevered stairs
- Corbel arch
- Euler–Bernoulli beam theory
- Grand Canyon Skywalk
- Knudsen force in the context of microcantilevers
- Orthodontics
- Statics

[helpful hint: the flag is in flag.txt in the current directory.]
cat: each: No such file or directory
cat: cantilever: No such file or directory
cat: used: No such file or directory
cat: to: No such file or directory
cat: support: No such file or directory
cat: one: No such file or directory
cat: end: No such file or directory
cat: of: No such file or directory
cat: a: No such file or directory
cat: central: No such file or directory
cat: section.: No such file or directory
cat: The: No such file or directory
cat: Forth: No such file or directory
cat: Bridge: No such file or directory
cat: in: No such file or directory
cat: Scotland: No such file or directory
cat: is: No such file or directory
cat: an: No such file or directory
cat: example: No such file or directory
cat: of: No such file or directory
cat: a: No such file or directory
cat: cantilever: No such file or directory
cat: truss: No such file or directory
cat: bridge.: No such file or directory
cat: A: No such file or directory
cat: cantilever: No such file or directory
cat: in: No such file or directory
cat: a: No such file or directory
cat: traditionally: No such file or directory
cat: timber: No such file or directory
cat: framed: No such file or directory
cat: building: No such file or directory
cat: is: No such file or directory
cat: called: No such file or directory
cat: a: No such file or directory
cat: jetty: No such file or directory
cat: or: No such file or directory
cat: forebay.: No such file or directory
cat: In: No such file or directory
cat: the: No such file or directory
cat: southern: No such file or directory
cat: United: No such file or directory
cat: States,: No such file or directory
cat: a: No such file or directory
cat: historic: No such file or directory
cat: barn: No such file or directory
cat: type: No such file or directory
cat: is: No such file or directory
cat: the: No such file or directory
cat: cantilever: No such file or directory
cat: barn: No such file or directory
cat: of: No such file or directory
cat: log: No such file or directory
cat: construction.: No such file or directory
cat: Temporary: No such file or directory
cat: cantilevers: No such file or directory
cat: are: No such file or directory
cat: often: No such file or directory
cat: used: No such file or directory
cat: in: No such file or directory
cat: construction.: No such file or directory
cat: The: No such file or directory
cat: partially: No such file or directory
cat: constructed: No such file or directory
cat: structure: No such file or directory
cat: creates: No such file or directory
cat: a: No such file or directory
cat: cantilever,: No such file or directory
cat: but: No such file or directory
cat: the: No such file or directory
cat: completed: No such file or directory
cat: structure: No such file or directory
cat: does: No such file or directory
cat: not: No such file or directory
cat: act: No such file or directory
cat: as: No such file or directory
cat: a: No such file or directory
cat: cantilever.: No such file or directory
cat: This: No such file or directory
cat: is: No such file or directory
cat: very: No such file or directory
cat: helpful: No such file or directory
cat: when: No such file or directory
cat: temporary: No such file or directory
cat: supports,: No such file or directory
cat: or: No such file or directory
cat: falsework,: No such file or directory
cat: cannot: No such file or directory
cat: be: No such file or directory
cat: used: No such file or directory
cat: to: No such file or directory
cat: support: No such file or directory
cat: the: No such file or directory
cat: structure: No such file or directory
cat: while: No such file or directory
cat: it: No such file or directory
cat: is: No such file or directory
cat: being: No such file or directory
cat: built: No such file or directory
cat: '(e.g.,': No such file or directory
cat: over: No such file or directory
cat: a: No such file or directory
cat: busy: No such file or directory
cat: roadway: No such file or directory
cat: or: No such file or directory
cat: river,: No such file or directory
cat: or: No such file or directory
cat: in: No such file or directory
cat: a: No such file or directory
cat: deep: No such file or directory
cat: 'valley).': No such file or directory
cat: Therefore,: No such file or directory
cat: some: No such file or directory
cat: truss: No such file or directory
cat: arch: No such file or directory
cat: bridges: No such file or directory
cat: '(see': No such file or directory
cat: Navajo: No such file or directory
cat: 'Bridge)': No such file or directory
cat: are: No such file or directory
cat: built: No such file or directory
cat: from: No such file or directory
cat: each: No such file or directory
cat: side: No such file or directory
cat: as: No such file or directory
cat: cantilevers: No such file or directory
cat: until: No such file or directory
cat: the: No such file or directory
cat: spans: No such file or directory
cat: reach: No such file or directory
cat: each: No such file or directory
cat: other: No such file or directory
cat: and: No such file or directory
cat: are: No such file or directory
cat: then: No such file or directory
cat: jacked: No such file or directory
cat: apart: No such file or directory
cat: to: No such file or directory
cat: stress: No such file or directory
cat: them: No such file or directory
cat: in: No such file or directory
cat: compression: No such file or directory
cat: before: No such file or directory
cat: finally: No such file or directory
cat: joining.: No such file or directory
cat: Nearly: No such file or directory
cat: all: No such file or directory
cat: cable-stayed: No such file or directory
cat: bridges: No such file or directory
cat: are: No such file or directory
cat: built: No such file or directory
cat: using: No such file or directory
cat: cantilevers: No such file or directory
cat: as: No such file or directory
cat: this: No such file or directory
cat: is: No such file or directory
cat: one: No such file or directory
cat: of: No such file or directory
cat: their: No such file or directory
cat: chief: No such file or directory
cat: advantages.: No such file or directory
cat: Many: No such file or directory
cat: box: No such file or directory
cat: girder: No such file or directory
cat: bridges: No such file or directory
cat: are: No such file or directory
cat: built: No such file or directory
cat: segmentally,: No such file or directory
cat: or: No such file or directory
cat: in: No such file or directory
cat: short: No such file or directory
cat: pieces.: No such file or directory
cat: This: No such file or directory
cat: type: No such file or directory
cat: of: No such file or directory
cat: construction: No such file or directory
cat: lends: No such file or directory
cat: itself: No such file or directory
cat: well: No such file or directory
cat: to: No such file or directory
cat: balanced: No such file or directory
cat: cantilever: No such file or directory
cat: construction: No such file or directory
cat: where: No such file or directory
cat: the: No such file or directory
cat: bridge: No such file or directory
cat: is: No such file or directory
cat: built: No such file or directory
cat: in: No such file or directory
cat: both: No such file or directory
cat: directions: No such file or directory
cat: from: No such file or directory
cat: a: No such file or directory
cat: single: No such file or directory
cat: support.: No such file or directory
cat: These: No such file or directory
cat: structures: No such file or directory
cat: rely: No such file or directory
cat: heavily: No such file or directory
cat: on: No such file or directory
cat: torque: No such file or directory
cat: and: No such file or directory
cat: rotational: No such file or directory
cat: equilibrium: No such file or directory
cat: for: No such file or directory
cat: their: No such file or directory
cat: stability.: No such file or directory
cat: In: No such file or directory
cat: an: No such file or directory
cat: architectural: No such file or directory
cat: application,: No such file or directory
cat: Frank: No such file or directory
cat: Lloyd: No such file or directory
cat: 'Wrights Fallingwater used cantilevers to project large balconies. The East Stand at Elland Road Stadium in Leeds was, when completed, the largest cantilever stand in the world[2] holding 17,000 spectators. The roof built over the stands at Old Trafford uses a cantilever so that no supports will block views of the field. The old (now demolished) Miami Stadium had a similar roof over the spectator area. The largest cantilevered roof in Europe is located at St James': File name too long
cat: Park: No such file or directory
cat: in: No such file or directory
cat: Newcastle-Upon-Tyne,: No such file or directory
cat: the: No such file or directory
cat: home: No such file or directory
cat: stadium: No such file or directory
cat: of: No such file or directory
cat: Newcastle: No such file or directory
cat: United: No such file or directory
cat: 'F.C.[3][4]': No such file or directory
cat: Less: No such file or directory
cat: obvious: No such file or directory
cat: examples: No such file or directory
cat: of: No such file or directory
cat: cantilevers: No such file or directory
cat: are: No such file or directory
cat: free-standing: No such file or directory
cat: '(vertical)': No such file or directory
cat: radio: No such file or directory
cat: towers: No such file or directory
cat: without: No such file or directory
cat: guy-wires,: No such file or directory
cat: and: No such file or directory
cat: chimneys,: No such file or directory
cat: which: No such file or directory
cat: resist: No such file or directory
cat: being: No such file or directory
cat: blown: No such file or directory
cat: over: No such file or directory
cat: by: No such file or directory
cat: the: No such file or directory
cat: wind: No such file or directory
cat: through: No such file or directory
cat: cantilever: No such file or directory
cat: action: No such file or directory
cat: at: No such file or directory
cat: their: No such file or directory
cat: base.: No such file or directory
cat: The: No such file or directory
cat: cantilever: No such file or directory
cat: is: No such file or directory
cat: commonly: No such file or directory
cat: used: No such file or directory
cat: in: No such file or directory
cat: the: No such file or directory
cat: wings: No such file or directory
cat: of: No such file or directory
cat: fixed-wing: No such file or directory
cat: aircraft.: No such file or directory
cat: Early: No such file or directory
cat: aircraft: No such file or directory
cat: had: No such file or directory
cat: light: No such file or directory
cat: structures: No such file or directory
cat: which: No such file or directory
cat: were: No such file or directory
cat: braced: No such file or directory
A cantilever is a rigid structural element that extends horizontally and is unsupported at one end. Typically it extends from a flat vertical surface such as a wall, to which it must be firmly attached. Like other structural elements, a cantilever can be formed as a beam, plate, truss, or slab.

When subjected to a structural load at its far, unsupported end, the cantilever carries the load to the support where it applies a shear stress and a bending moment.[1]

Cantilever construction allows overhanging structures without additional support.

Cantilevers are widely found in construction, notably in cantilever bridges and balconies (see corbel). In cantilever bridges, the cantilevers are usually built as pairs, with each cantilever used to support one end of a central section. The Forth Bridge in Scotland is an example of a cantilever truss bridge. A cantilever in a traditionally timber framed building is called a jetty or forebay. In the southern United States, a historic barn type is the cantilever barn of log construction.

Temporary cantilevers are often used in construction. The partially constructed structure creates a cantilever, but the completed structure does not act as a cantilever. This is very helpful when temporary supports, or falsework, cannot be used to support the structure while it is being built (e.g., over a busy roadway or river, or in a deep valley). Therefore, some truss arch bridges (see Navajo Bridge) are built from each side as cantilevers until the spans reach each other and are then jacked apart to stress them in compression before finally joining. Nearly all cable-stayed bridges are built using cantilevers as this is one of their chief advantages. Many box girder bridges are built segmentally, or in short pieces. This type of construction lends itself well to balanced cantilever construction where the bridge is built in both directions from a single support.

These structures rely heavily on torque and rotational equilibrium for their stability.

In an architectural application, Frank Lloyd Wright's Fallingwater used cantilevers to project large balconies. The East Stand at Elland Road Stadium in Leeds was, when completed, the largest cantilever stand in the world[2] holding 17,000 spectators. The roof built over the stands at Old Trafford uses a cantilever so that no supports will block views of the field. The old (now demolished) Miami Stadium had a similar roof over the spectator area. The largest cantilevered roof in Europe is located at St James' Park in Newcastle-Upon-Tyne, the home stadium of Newcastle United F.C.[3][4]

Less obvious examples of cantilevers are free-standing (vertical) radio towers without guy-wires, and chimneys, which resist being blown over by the wind through cantilever action at their base.

The cantilever is commonly used in the wings of fixed-wing aircraft. Early aircraft had light structures which were braced with wires and struts. However, these introduced aerodynamic drag which limited performance. While it is heavier, the cantilever avoids this issue and allows the plane to fly faster.

Hugo Junkers pioneered the cantilever wing in 1915. Only a dozen years after the Wright Brothers' initial flights, Junkers endeavored to eliminate virtually all major external bracing members in order to decrease airframe drag in flight. The result of this endeavor was the Junkers J 1 pioneering all-metal monoplane of late 1915, designed from the start with all-metal cantilever wing panels. About a year after the initial success of the Junkers J 1, Reinhold Platz of Fokker also achieved success with a cantilever-winged sesquiplane built instead with wooden materials, the Fokker V.1.

In the cantilever wing, one or more strong beams, called spars, run along the span of the wing. The end fixed rigidly to the central fuselage is known as the root and the far end as the tip. In flight, the wings generate lift and the spars carry this load through to the fuselage.

To resist horizontal shear stress from either drag or engine thrust, the wing must also form a stiff cantilever in the horizontal plane. A single-spar design will usually be fitted with a second smaller drag-spar nearer the trailing edge, braced to the main spar via additional internal members or a stressed skin. The wing must also resist twisting forces, achieved by cross-bracing or otherwise stiffening the main structure.

Cantilever wings require much stronger and heavier spars than would otherwise be needed in a wire-braced design. However, as the speed of the aircraft increases, the drag of the bracing increases sharply, while the wing structure must be strengthened, typically by increasing the strength of the spars and the thickness of the skinning. At speeds of around 200 miles per hour (320 km/h) the drag of the bracing becomes excessive and the wing strong enough to be made a cantilever without excess weight penalty. Increases in engine power through the late 1920s and early 1930s raised speeds through this zone and by the late 1930s cantilever wings had almost wholly superseded braced ones.[5] Other changes such as enclosed cockpits, retractable undercarriage, landing flaps and stressed-skin construction furthered the design revolution, with the pivotal moment widely acknowledged to be the MacRobertson England-Australia air race of 1934, which was won by a de Havilland DH.88 Comet.[6]

Currently, cantilever wings are almost universal with bracing only being used for some slower aircraft where a lighter weight is prioritized over speed, such as in the ultralight class.

Cantilevered beams are the most ubiquitous structures in the field of microelectromechanical systems (MEMS). An early example of a MEMS cantilever is the Resonistor,[7][8] an electromechanical monolithic resonator. MEMS cantilevers are commonly fabricated from silicon (Si), silicon nitride (Si3N4), or polymers. The fabrication process typically involves undercutting the cantilever structure to release it, often with an anisotropic wet or dry etching technique. Without cantilever transducers, atomic force microscopy would not be possible. A large number of research groups are attempting to develop cantilever arrays as biosensors for medical diagnostic applications. MEMS cantilevers are also finding application as radio frequency filters and resonators. The MEMS cantilevers are commonly made as unimorphs or bimorphs.

Two equations are key to understanding the behavior of MEMS cantilevers. The first is Stoney's formula, which relates cantilever end deflection δ to applied stress σ:

[math equations]

The principal advantage of MEMS cantilevers is their cheapness and ease of fabrication in large arrays. The challenge for their practical application lies in the square and cubic dependences of cantilever performance specifications on dimensions. These superlinear dependences mean that cantilevers are quite sensitive to variation in process parameters, particularly the thickness as this is generally difficult to accurately measure.[9] However, it has been shown that microcantilever thicknesses can be precisely measured and that this variation can be quantified.[10] Controlling residual stress can also be difficult.

A chemical sensor can be obtained by coating a recognition receptor layer over the upper side of a microcantilever beam.[12] A typical application is the immunosensor based on an antibody layer that interacts selectively with a particular immunogen and reports about its content in a specimen. In the static mode of operation, the sensor response is represented by the beam bending with respect to a reference microcantilever. Alternatively, microcantilever sensors can be operated in the dynamic mode. In this case, the beam vibrates at its resonance frequency and a variation in this parameter indicates the concentration of the analyte. Recently, microcantilevers have been fabricated that are porous, allowing for a much larger surface area for analyte to bind to, increasing sensitivity by raising the ratio of the analyte mass to the device mass.[13] Surface stress on microcantilever, due to receptor-target binding, which produces cantilever deflection can be analyzed using optical methods like laser interferometry. Zhao et al., also showed that by changing the attachment protocol of the receptor on the microcantilever surface, the sensitivity can be further improved when the surface stress generated on the microcantilever is taken as the sensor signal.[14]

See also
- Applied mechanics
- Cantilever bicycle brakes
- Cantilever bicycle frame
- Cantilever chair
- Cantilever method
- Cantilevered stairs
- Corbel arch
- Euler–Bernoulli beam theory
- Grand Canyon Skywalk
- Knudsen force in the context of microcantilevers
- Orthodontics
- Statics

[helpful hint: the flag is in flag.txt in the current directory.]
cat: wires: No such file or directory
cat: and: No such file or directory
cat: struts.: No such file or directory
cat: However,: No such file or directory
cat: these: No such file or directory
cat: introduced: No such file or directory
cat: aerodynamic: No such file or directory
cat: drag: No such file or directory
cat: which: No such file or directory
cat: limited: No such file or directory
cat: performance.: No such file or directory
cat: While: No such file or directory
cat: it: No such file or directory
cat: is: No such file or directory
cat: heavier,: No such file or directory
cat: the: No such file or directory
cat: cantilever: No such file or directory
cat: avoids: No such file or directory
cat: this: No such file or directory
cat: issue: No such file or directory
cat: and: No such file or directory
cat: allows: No such file or directory
cat: the: No such file or directory
cat: plane: No such file or directory
cat: to: No such file or directory
cat: fly: No such file or directory
cat: faster.: No such file or directory
cat: Hugo: No such file or directory
cat: Junkers: No such file or directory
cat: pioneered: No such file or directory
cat: the: No such file or directory
cat: cantilever: No such file or directory
cat: wing: No such file or directory
cat: in: No such file or directory
cat: 1915.: No such file or directory
cat: Only: No such file or directory
cat: a: No such file or directory
cat: dozen: No such file or directory
cat: years: No such file or directory
cat: after: No such file or directory
cat: the: No such file or directory
cat: Wright: No such file or directory
```
###### Each occurrence of `with` causes `cat` to print the entire file again. Marvelous!

Instead, we can use `grep` to get only the line containing the "helpful hint":
```bash
kevin@ky28059:~$ nc localhost 7072
$ cat with | grep .txt
[helpful hint: the flag is in flag.txt in the current directory.]
```
Then, `xargs cat` on that line to get the flag.
```bash
kevin@ky28059:~$ nc localhost 7072
$ cat with | grep .txt | xargs cat
cat: '[helpful': No such file or directory
cat: 'hint:': No such file or directory
cat: the: No such file or directory
cat: flag: No such file or directory
cat: is: No such file or directory
cat: in: No such file or directory
bctf{owwwww_th4t_hurt}cat: in: No such file or directory
cat: the: No such file or directory
cat: current: No such file or directory
cat: directory.]: No such file or directory
```
