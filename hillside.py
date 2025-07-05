import bpy
import random
from mathutils import Vector

# --------------- PARAMETERS ---------------
NUM_ROCKS = 25
NUM_STONES = 20
ROCK_SIZE = 0.2  # meters (40 cm)
STONE_SIZE = 0.03  # meters (3 cm)
HILL_TILT_DEG = 35
HILL_LENGTH = 33  # <<-- Made hillside much longer (was 15)
HILL_WIDTH = 8
POWDER_PARTICLES = 15000
DUST_VOLUME_SIZE = (8, 3, 2)
SCENE = bpy.context.scene

# --------------- CLEANUP ---------------
bpy.ops.object.select_all(action='SELECT')
bpy.ops.object.delete(use_global=False)

# --------------- HILLSIDE ---------------
bpy.ops.mesh.primitive_plane_add(size=1, location=(0, 0, 0))
hillside = bpy.context.active_object
hillside.scale = (HILL_LENGTH, HILL_WIDTH, 1)
hillside.rotation_euler[0] = HILL_TILT_DEG * 3.1416 / 180
bpy.ops.object.transform_apply(location=False, rotation=True, scale=True)

# --- Much More Sophisticated Hillside Geometry/Displacement ---
# Add multiple displacement layers, large-scale and fine detail
# 1. Base displacement for big undulations
mod1 = hillside.modifiers.new('DisplaceBig', 'DISPLACE')
tex1 = bpy.data.textures.new('HillBigTex', 'CLOUDS')
tex1.noise_scale = 7.0
tex1.nabla = 0.07
mod1.texture = tex1
mod1.strength = 2.5
mod1.mid_level = 0.45

# 2. Medium-scale erosion and flow effects
mod2 = hillside.modifiers.new('DisplaceMed', 'DISPLACE')
tex2 = bpy.data.textures.new('HillMedTex', 'VORONOI')
tex2.noise_scale = 2.2
mod2.texture = tex2
mod2.strength = 0.8
mod2.mid_level = 0.65

# 3. Fine rock/grit displacement (adds realism)
mod3 = hillside.modifiers.new('DisplaceFine', 'DISPLACE')
tex3 = bpy.data.textures.new('HillFineTex', 'MUSGRAVE')
tex3.noise_scale = 0.34
mod3.texture = tex3
mod3.strength = 0.27
mod3.mid_level = 0.48

# 4. Subdivide for higher mesh detail (needed for realistic displacement)
bpy.context.view_layer.objects.active = hillside
subdiv = hillside.modifiers.new('Subdivision', 'SUBSURF')
subdiv.levels = 4
subdiv.render_levels = 5

bpy.ops.object.modifier_move_to_index(modifier="Subdivision", index=0)  # Subdivide first
bpy.ops.object.shade_smooth()

# --- Add subtle color variation to the hillside (vertex colors) for realism ---
if not hillside.data.vertex_colors:
    hillside.data.vertex_colors.new(name="HillVColor")
vcol = hillside.data.vertex_colors["HillVColor"]
for poly in hillside.data.polygons:
    for loop_index in poly.loop_indices:
        vcol.data[loop_index].color = (
            0.93 + random.uniform(-0.03, 0.03),
            0.88 + random.uniform(-0.02, 0.02),
            0.74 + random.uniform(-0.04, 0.04),
            1.0
        )

# --------------- ROCK SHAPE FROM IMAGE (image3) ---------------
def create_rock(location, size):
    # Irregular low-poly rock - inspired by image3
    bpy.ops.mesh.primitive_ico_sphere_add(subdivisions=1, radius=size, location=location)
    rock = bpy.context.active_object
    for v in rock.data.vertices:
        v.co += Vector((random.uniform(-0.18,0.18)*size, random.uniform(-0.18,0.18)*size, random.uniform(-0.1,0.25)*size))
    rock.name = "Rock"
    rock.data.name = "RockMesh"
    return rock

def create_stone(location, size):
    bpy.ops.mesh.primitive_ico_sphere_add(subdivisions=1, radius=size, location=location)
    stone = bpy.context.active_object
    for v in stone.data.vertices:
        v.co += Vector((random.uniform(-0.06,0.06)*size, random.uniform(-0.06,0.06)*size, random.uniform(-0.03,0.07)*size))
    stone.name = "Stone"
    return stone

# --------------- ADD ROCKS AND STONES (image3 shape) ---------------
rock_objs = []
for i in range(NUM_ROCKS):
    x = random.uniform(-HILL_LENGTH*0.4, HILL_LENGTH*0.4)
    y = random.uniform(-HILL_WIDTH*0.4, HILL_WIDTH*0.4)
    z = 2 + random.uniform(0, 1.5)
    rock = create_rock((x, y, z), ROCK_SIZE)
    rock_objs.append(rock)

stone_objs = []
for i in range(NUM_STONES):
    x = random.uniform(-HILL_LENGTH*0.4, HILL_LENGTH*0.4)
    y = random.uniform(-HILL_WIDTH*0.4, HILL_WIDTH*0.4)
    z = 2.1 + random.uniform(0, 1.2)
    stone = create_stone((x, y, z), STONE_SIZE)
    stone_objs.append(stone)

# --------------- PHYSICS: FALL & SLIDE DOWN THE SLOPE ---------------
for obj in rock_objs + stone_objs:
    obj.select_set(True)
    bpy.context.view_layer.objects.active = obj
    bpy.ops.rigidbody.object_add()
    obj.rigid_body.type = 'ACTIVE'
    obj.rigid_body.friction = 0.46
    obj.rigid_body.restitution = 0.21
    obj.select_set(False)

hillside.select_set(True)
bpy.context.view_layer.objects.active = hillside
bpy.ops.rigidbody.object_add()
hillside.rigid_body.type = 'PASSIVE'
hillside.rigid_body.friction = 0.74
hillside.rigid_body.restitution = 0.13
hillside.select_set(False)

# --------------- POWDER & DUST (Particles, Volumes) ---------------
# Powder: sand particle system (refer to image2 white puffs)
powder_emitter = hillside.copy()
powder_emitter.data = hillside.data.copy()
SCENE.collection.objects.link(powder_emitter)
powder_emitter.name = "PowderEmitter"
powder_emitter.location.z += 0.25

ps = powder_emitter.modifiers.new("PowderParticles", type='PARTICLE_SYSTEM')
psys = powder_emitter.particle_systems[0]
psys.settings.count = POWDER_PARTICLES
psys.settings.frame_start = 1
psys.settings.frame_end = 30
psys.settings.lifetime = 70
psys.settings.emit_from = 'FACE'
psys.settings.normal_factor = 0.6
psys.settings.physics_type = 'NEWTON'
psys.settings.particle_size = 0.02
psys.settings.render_type = 'HALO'
psys.settings.use_rotations = True
psys.settings.angular_velocity_mode = 'RADIAL'
psys.settings.effector_weights.gravity = 0.5

# Dust: smoke volume (refer to image1 & image2)
bpy.ops.mesh.primitive_cube_add(size=1, location=(0, 0, 1.2))
dust_volume = bpy.context.active_object
dust_volume.scale = (DUST_VOLUME_SIZE[0]/2, DUST_VOLUME_SIZE[1]/2, DUST_VOLUME_SIZE[2]/2)
bpy.ops.object.quick_smoke()
dust_volume.modifiers["Smoke"].flow_settings.smoke_color = (0.94, 0.91, 0.85)  # dusty white
dust_volume.modifiers["Smoke"].flow_settings.density = 0.25
dust_volume.modifiers["Smoke"].flow_settings.temperature = 0.3

# --------------- CAMERA & LIGHTING ---------------
bpy.ops.object.camera_add(location=(0, -22, 11), rotation=(1.05, 0, 0))
bpy.ops.object.light_add(type='SUN', location=(0, 0, 16))
bpy.context.active_object.data.energy = 5

# --------------- MATERIALS ---------------
def rocky_mat():
    mat = bpy.data.materials.new("RockyMat")
    mat.use_nodes = True
    nodes = mat.node_tree.nodes
    bsdf = nodes.get('Principled BSDF')
    if bsdf:
        bsdf.inputs['Base Color'].default_value = (0.84, 0.8, 0.75, 1.0)
        bsdf.inputs['Roughness'].default_value = 0.9
    return mat

def powder_mat():
    mat = bpy.data.materials.new("PowderMat")
    mat.use_nodes = True
    nodes = mat.node_tree.nodes
    bsdf = nodes.get('Principled BSDF')
    if bsdf:
        bsdf.inputs['Base Color'].default_value = (0.93, 0.9, 0.8, 1.0)
        bsdf.inputs['Roughness'].default_value = 0.98
    return mat

mat_rock = rocky_mat()
mat_powder = powder_mat()
for obj in rock_objs:
    obj.data.materials.append(mat_rock)
for obj in stone_objs:
    obj.data.materials.append(mat_rock)
hillside.data.materials.append(mat_powder)

# --------------- SUMMARY ---------------
print("Rocky hillside with falling rocks, stones, powder, and dust set up. Referenced images used for shapes and effects.")

# To run: In Blender's Text Editor, paste and run this script.
# You may want to bake physics and smoke for realism after running the script.
